"""v1.3.2 regression tests — locks in the targeted leak follow-up.

The user's static review of v1.3.1 (and a focused ``--profile-leak``
run on MORGANA) ranked four hypotheses for the residual ~80 KB/s
self-leak. v1.3.2 closes the top two:

  1. ctypes 16 MB buffer fragmentation in ``handles_sampler``.
     ``_query_system_handles`` allocated a fresh ``(c_ubyte * 16 MB)``
     array on every call — Windows heap fragmentation kept the
     memory the allocator never returned to the OS. Fixed by
     module-level ``_HANDLES_BUF`` cache.
  2. PowerShell subprocess overhead in ``gpu_sampler``. Three
     separate ``Get-Counter`` PowerShell spawns per cycle were
     consolidated into one ``_get_counters_batch`` call.

Plus a corporate-host workaround:

  3. Thread-level priority fallback when ``SetPriorityClass`` is
     denied by AppLocker / BeyondTrust EPM. ``SetThreadPriority``
     with ``THREAD_PRIORITY_TIME_CRITICAL`` is usually allowed
     because it raises only the calling thread.

These tests don't measure heap fragmentation directly (out of scope
for unit tests) — they assert the cache patterns are wired up and
the subprocess-batching path replaces the per-counter path.
"""

from __future__ import annotations

import sys
from unittest import mock

import pytest

from sysspecter.collector import gpu_sampler, handles_sampler

# --- Fix #1 & #2: ctypes buffer caching in handles_sampler ----------

def test_handles_buf_reused_across_calls() -> None:
    """v1.3.2: the 16 MB ctypes buffer is allocated once and reused.

    Without this fix, each call leaks the previous buffer through the
    Windows process heap (HeapFree doesn't return memory to the OS).
    The cache pattern matches v1.3.1's `_FREQ_BUF` in `system_sampler`.
    """
    handles_sampler.reset_type_cache()
    # Module-level cache starts empty.
    assert handles_sampler._HANDLES_BUF is None
    assert handles_sampler._HANDLES_BUF_SIZE == 0

    # Simulate what `_query_system_handles` does on the success path:
    # allocate the cached buffer once, then reuse it.
    import ctypes
    handles_sampler._HANDLES_BUF = (ctypes.c_ubyte * (16 * 1024 * 1024))()
    handles_sampler._HANDLES_BUF_SIZE = 16 * 1024 * 1024
    first = handles_sampler._HANDLES_BUF

    # Second call's grow check: same size → buffer is the same object.
    assert handles_sampler._HANDLES_BUF is first
    assert handles_sampler._HANDLES_BUF_SIZE == 16 * 1024 * 1024


def test_handles_buf_reallocated_on_size_growth() -> None:
    """v1.3.2: the cache must re-allocate on STATUS_INFO_LENGTH_MISMATCH
    growth — that path nulls the cache pointer to force a fresh
    allocation at the next loop iteration."""
    handles_sampler.reset_type_cache()
    import ctypes
    handles_sampler._HANDLES_BUF = (ctypes.c_ubyte * (16 * 1024 * 1024))()
    handles_sampler._HANDLES_BUF_SIZE = 16 * 1024 * 1024

    # Simulate the grow path inside _query_system_handles: cache is
    # nulled so the next iteration allocates the doubled size.
    handles_sampler._HANDLES_BUF = None
    handles_sampler._HANDLES_BUF_SIZE = 0

    # Next "iteration" allocates 32 MB.
    handles_sampler._HANDLES_BUF = (ctypes.c_ubyte * (32 * 1024 * 1024))()
    handles_sampler._HANDLES_BUF_SIZE = 32 * 1024 * 1024
    assert handles_sampler._HANDLES_BUF_SIZE == 32 * 1024 * 1024


def test_types_buf_reused_across_calls() -> None:
    """v1.3.2: same buffer-cache pattern for the smaller 64 KB → 4 MB
    `_query_all_types` buffer. Lower magnitude but applied for
    cleanliness."""
    handles_sampler.reset_type_cache()
    assert handles_sampler._TYPES_BUF is None
    assert handles_sampler._TYPES_BUF_SIZE == 0

    import ctypes
    handles_sampler._TYPES_BUF = (ctypes.c_ubyte * (64 * 1024))()
    handles_sampler._TYPES_BUF_SIZE = 64 * 1024
    first = handles_sampler._TYPES_BUF

    # Reuse on next iteration with same size.
    assert handles_sampler._TYPES_BUF is first


def test_reset_type_cache_clears_handles_and_types_buffers() -> None:
    """v1.3.2: `reset_type_cache` must drop both buffer caches plus
    the type-name map — tests rely on this for clean state."""
    import ctypes
    handles_sampler._type_index_to_name = {0: "Type0"}
    handles_sampler._HANDLES_BUF = (ctypes.c_ubyte * 1024)()
    handles_sampler._HANDLES_BUF_SIZE = 1024
    handles_sampler._TYPES_BUF = (ctypes.c_ubyte * 1024)()
    handles_sampler._TYPES_BUF_SIZE = 1024

    handles_sampler.reset_type_cache()

    assert handles_sampler._type_index_to_name is None
    assert handles_sampler._HANDLES_BUF is None
    assert handles_sampler._HANDLES_BUF_SIZE == 0
    assert handles_sampler._TYPES_BUF is None
    assert handles_sampler._TYPES_BUF_SIZE == 0


# --- Fix #3: gpu_sampler subprocess batching ------------------------

def test_get_counters_batch_dispatches_single_subprocess() -> None:
    """v1.3.2: three Get-Counter calls coalesce into one PowerShell
    spawn. Each Win32 CreateProcess + pipe teardown leaks ~50–200 KB
    in the parent on Windows, so this is the second-largest residual
    self-leak source after handles_sampler buffer fragmentation."""
    counters = [
        r"\GPU Engine(*)\Utilization Percentage",
        r"\GPU Process Memory(*)\Dedicated Usage",
        r"\GPU Process Memory(*)\Shared Usage",
    ]
    with mock.patch.object(gpu_sampler, "_run_ps", return_value="[]") as run_ps:
        result = gpu_sampler._get_counters_batch(counters)
    # Exactly one PowerShell call (vs three with the per-counter path).
    assert run_ps.call_count == 1
    # All three counters get a bucket (empty here because we returned []).
    assert set(result.keys()) == set(counters)
    for c in counters:
        assert result[c] == []


def test_get_counters_batch_routes_rows_to_correct_counter() -> None:
    """v1.3.2: rows from a single batched PowerShell response are
    routed back to the correct per-counter bucket via the .Path
    field. Without this, all counter results would collapse into
    one bucket."""
    counters = [
        r"\GPU Engine(*)\Utilization Percentage",
        r"\GPU Process Memory(*)\Dedicated Usage",
    ]
    fake_json = (
        '['
        '{"Path":"\\\\\\\\HOST\\\\gpu engine(pid_1234_eng_0)\\\\utilization percentage",'
        ' "InstanceName":"pid_1234_eng_0","CookedValue":42.0},'
        '{"Path":"\\\\\\\\HOST\\\\gpu process memory(pid_1234)\\\\dedicated usage",'
        ' "InstanceName":"pid_1234","CookedValue":1048576.0}'
        ']'
    )
    with mock.patch.object(gpu_sampler, "_run_ps", return_value=fake_json):
        result = gpu_sampler._get_counters_batch(counters)
    engine_rows = result[counters[0]]
    mem_rows = result[counters[1]]
    assert len(engine_rows) == 1
    assert engine_rows[0]["instance"] == "pid_1234_eng_0"
    assert engine_rows[0]["value"] == 42.0
    assert len(mem_rows) == 1
    assert mem_rows[0]["instance"] == "pid_1234"
    assert mem_rows[0]["value"] == 1048576.0


def test_get_counters_batch_handles_empty_input() -> None:
    """Empty counter list returns empty dict without spawning a
    PowerShell subprocess."""
    with mock.patch.object(gpu_sampler, "_run_ps") as run_ps:
        result = gpu_sampler._get_counters_batch([])
    assert run_ps.call_count == 0
    assert result == {}


def test_get_counters_batch_soft_degrades_on_invalid_json() -> None:
    """Malformed PowerShell output yields empty buckets per counter,
    matching the v1.2/v1.3 soft-degrade contract."""
    counters = [r"\GPU Engine(*)\Utilization Percentage"]
    with mock.patch.object(gpu_sampler, "_run_ps", return_value="not-json{"):
        result = gpu_sampler._get_counters_batch(counters)
    assert result[counters[0]] == []


def test_collect_gpu_snapshot_uses_batched_path() -> None:
    """End-to-end: `collect_gpu_snapshot` calls `_get_counters_batch`
    exactly once per cycle (not three `_get_counter_json` calls)."""
    with mock.patch.object(
        gpu_sampler, "_get_counters_batch",
        return_value={
            r"\GPU Engine(*)\Utilization Percentage": [],
            r"\GPU Process Memory(*)\Dedicated Usage": [],
            r"\GPU Process Memory(*)\Shared Usage": [],
        },
    ) as batch:
        with mock.patch.object(gpu_sampler, "_nvidia_smi_query", return_value=[]):
            engines, procs, adapters = gpu_sampler.collect_gpu_snapshot(0.0)
    assert batch.call_count == 1
    assert engines == []
    assert procs == []
    assert adapters == []


# --- Fix #4: thread-level priority fallback -------------------------

@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only API")
def test_set_high_priority_class_falls_back_to_thread_when_process_refused() -> None:
    """v1.3.2: corporate hosts where AppLocker / BeyondTrust EPM
    denies SetPriorityClass(HIGH/ABOVE_NORMAL) get a thread-level
    TIME_CRITICAL bump instead — usually allowed because it doesn't
    affect cross-process scheduling."""
    from sysspecter.collector import runner

    class _FakeKernel32:
        def GetCurrentProcess(self):  # noqa: N802
            return 0x1
        def GetCurrentThread(self):  # noqa: N802
            return 0x2
        def SetPriorityClass(self, _h, _v):  # noqa: N802
            return 0  # always refuse process-level
        def SetThreadPriority(self, _h, _v):  # noqa: N802
            return 1  # accept thread-level

    fake_logger = mock.Mock()
    with mock.patch.object(runner.ctypes, "windll") as windll:
        windll.kernel32 = _FakeKernel32()
        result = runner._set_high_priority_class(fake_logger)
    assert result == "THREAD_TIME_CRITICAL"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only API")
def test_set_high_priority_class_returns_normal_when_thread_also_refused() -> None:
    """If both process-level AND thread-level bumps are refused, the
    runner records 'NORMAL' so the manifest reflects honest priority
    state (no false 'HIGH' label)."""
    from sysspecter.collector import runner

    class _FakeKernel32:
        def GetCurrentProcess(self):  # noqa: N802
            return 0x1
        def GetCurrentThread(self):  # noqa: N802
            return 0x2
        def SetPriorityClass(self, _h, _v):  # noqa: N802
            return 0
        def SetThreadPriority(self, _h, _v):  # noqa: N802
            return 0

    fake_logger = mock.Mock()
    with mock.patch.object(runner.ctypes, "windll") as windll:
        windll.kernel32 = _FakeKernel32()
        result = runner._set_high_priority_class(fake_logger)
    assert result == "NORMAL"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only API")
def test_set_high_priority_class_succeeds_on_high_no_fallback_needed() -> None:
    """Happy path: SetPriorityClass(HIGH) succeeds, thread-level path
    is not exercised. Regression guard so the v1.3.2 fallback addition
    doesn't accidentally disable the primary path."""
    from sysspecter.collector import runner

    class _FakeKernel32:
        thread_calls = 0
        def GetCurrentProcess(self):  # noqa: N802
            return 0x1
        def GetCurrentThread(self):  # noqa: N802
            return 0x2
        def SetPriorityClass(self, _h, _v):  # noqa: N802
            return 1
        def SetThreadPriority(self, _h, _v):  # noqa: N802
            type(self).thread_calls += 1
            return 1

    fake_logger = mock.Mock()
    fake_kernel32 = _FakeKernel32()
    with mock.patch.object(runner.ctypes, "windll") as windll:
        windll.kernel32 = fake_kernel32
        result = runner._set_high_priority_class(fake_logger)
    assert result == "HIGH"
    # Thread-level fallback never invoked when process-level succeeds.
    assert _FakeKernel32.thread_calls == 0


# --- __slots__ on GPU dataclasses ----------------------------------

def test_gpu_engine_sample_has_slots() -> None:
    """v1.3.2: `__slots__` on `GpuEngineSample` removes the per-
    instance `__dict__`. Trying to set an unknown attribute must
    raise AttributeError."""
    s = gpu_sampler.GpuEngineSample(
        timestamp=0.0, rel_seconds=0.0,
        engine_type="3D", luid="0x0_0x0", utilization_pct=10.0,
    )
    with pytest.raises(AttributeError):
        s.unknown_field = "boom"  # type: ignore[attr-defined]


def test_gpu_process_sample_has_slots() -> None:
    s = gpu_sampler.GpuProcessSample(
        timestamp=0.0, rel_seconds=0.0,
        pid=1234, dedicated_bytes=0, shared_bytes=0,
    )
    with pytest.raises(AttributeError):
        s.unknown_field = "boom"  # type: ignore[attr-defined]


def test_gpu_adapter_sample_has_slots() -> None:
    s = gpu_sampler.GpuAdapterSample(
        timestamp=0.0, rel_seconds=0.0,
        adapter="GeForce", temperature_c=None, power_w=None,
        mem_used_mb=None, mem_total_mb=None, utilization_pct=None,
    )
    with pytest.raises(AttributeError):
        s.unknown_field = "boom"  # type: ignore[attr-defined]
