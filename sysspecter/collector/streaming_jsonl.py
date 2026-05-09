"""v1.3.0 Phase A.1 (Suspect 1): streaming JSONL appender.

The v1.2 runner accumulated `process_events` and `service_events` in
in-memory lists for the run's full duration, then wrote them as
single JSON arrays at end. On a 4-hour run those lists could grow to
tens of MB and were the prime suspect for the self-leak (~660 KB per
sample on MORGANA).

`StreamingJSONL` writes each batch as one JSON object per line to a
`.jsonl.partial` file, then **at run end** rewrites the file as a
single JSON array (so existing `analyzer/loader.py:_read_json`
consumers don't have to learn a new format). The atomic rewrite uses
a `.tmp` file + `os.replace` so a crash during finalisation never
leaves a half-written array.

In-memory state during the run is bounded: a small `deque(maxlen=N)`
ring buffer of the most-recent events for any "current state" GUI
query (none today, but cheap to keep). The list-of-everything is
gone.

Soft-degrades on every IO error path: if the JSONL file can't be
opened, the appender silently drops events and logs once. Better to
lose visibility than crash the runner.
"""

from __future__ import annotations

import json
import logging
import os
from collections import deque
from typing import IO, Any

_log = logging.getLogger("sysspecter.streaming_jsonl")


class StreamingJSONL:
    """Append-only JSONL writer with end-of-run JSON-array rewrite.

    Usage:
        events = StreamingJSONL(paths.process_events, recent_cap=1000)
        events.open()
        ...
        events.write_many(batch)              # in the loop, no in-memory growth
        ...
        events.finalize_as_json_array()       # at run end, atomic rewrite
        events.close()

    Or context-managed:
        with StreamingJSONL(path) as evs:
            evs.write_many(batch)
            evs.finalize_as_json_array()
    """

    def __init__(self, path: str, *, recent_cap: int = 1000) -> None:
        self.path = path
        self.partial_path = path + ".partial.jsonl"
        self._fh: IO[str] | None = None
        self._count = 0
        self._recent: deque[dict[str, Any]] = deque(maxlen=recent_cap)
        self._broken = False  # set True after a write error so we stop trying

    def open(self) -> None:
        try:
            self._fh = open(self.partial_path, "w", encoding="utf-8", newline="\n")
        except OSError as e:
            _log.warning("could not open partial file %s: %s",
                         self.partial_path, e)
            self._broken = True

    def write_many(self, items: list[dict[str, Any]]) -> None:
        if self._broken or self._fh is None or not items:
            return
        try:
            for item in items:
                self._fh.write(json.dumps(item, ensure_ascii=False, default=str))
                self._fh.write("\n")
                self._recent.append(item)
                self._count += 1
        except (OSError, TypeError, ValueError) as e:
            _log.warning("partial JSONL write failed: %s — disabling appender", e)
            self._broken = True

    def write(self, item: dict[str, Any]) -> None:
        self.write_many([item])

    def flush(self) -> None:
        if self._fh is not None:
            try:
                self._fh.flush()
            except OSError:
                pass

    @property
    def recent(self) -> list[dict[str, Any]]:
        """Snapshot copy of the in-memory ring buffer (small, capped)."""
        return list(self._recent)

    @property
    def count(self) -> int:
        return self._count

    def finalize_as_json_array(self) -> None:
        """Rewrite `<path>` as a single JSON array of every event we
        appended to the JSONL file. Atomic via tmp + os.replace.

        Back-compat: existing consumers of `process_events.json` /
        `service_events.json` use `json.load` and expect a list. This
        keeps that contract.
        """
        # Close the partial file first so the read below sees the full
        # contents on Windows (where open files can refuse re-read).
        if self._fh is not None:
            try:
                self._fh.flush()
                self._fh.close()
            except OSError:
                pass
            self._fh = None

        items: list[dict[str, Any]] = []
        if os.path.exists(self.partial_path):
            try:
                with open(self.partial_path, encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            items.append(json.loads(line))
                        except json.JSONDecodeError:
                            # Skip a single corrupt line rather than
                            # losing the whole array.
                            continue
            except OSError as e:
                _log.warning("could not read partial JSONL %s: %s",
                             self.partial_path, e)
                items = []

        tmp = self.path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(items, f, indent=2, ensure_ascii=False, default=str)
            os.replace(tmp, self.path)
        except OSError as e:
            _log.warning("could not write final JSON array to %s: %s",
                         self.path, e)
            # Try not to leave a stale .tmp behind.
            try:
                if os.path.exists(tmp):
                    os.remove(tmp)
            except OSError:
                pass
            return

        # Best-effort cleanup of the partial file. Keep it on failure
        # so the data isn't lost — the operator can recover manually.
        try:
            os.remove(self.partial_path)
        except OSError:
            pass

    def close(self) -> None:
        if self._fh is not None:
            try:
                self._fh.flush()
                self._fh.close()
            except OSError:
                pass
            self._fh = None

    def __enter__(self) -> StreamingJSONL:
        self.open()
        return self

    def __exit__(self, *exc) -> None:
        self.close()


# ---------------------------------------------------------------------------
# Streaming gap-statistics accumulator (used to replace observed_gaps list)
# ---------------------------------------------------------------------------

class StreamingGapStats:
    """O(1)-memory accumulator for cadence gap statistics.

    The v1.2 runner stored every per-tick gap in a `list[float]` for
    the run's full duration just to compute median / p95 / max at end.
    On a 4-hour 1 Hz run that's 14 400 floats ≈ 115 KB — small but
    unbounded in run length, and trivially replaceable with running
    estimators.

    For the v1.3 runner we use:
      - exact running max (trivial)
      - exact mean (online via Welford-style accumulator)
      - reservoir sample (size 2048) for percentile estimation —
        gives stable median / p95 with bounded memory regardless of
        how many gaps we observe.

    The reservoir uses Algorithm R (Vitter 1985) for unbiased uniform
    sampling. 2048 entries is plenty for stable p50 / p95 to within a
    few percent — and bounded at ~16 KB regardless of run length.
    """

    def __init__(self, *, reservoir_size: int = 2048) -> None:
        self._reservoir: list[float] = []
        self._reservoir_size = reservoir_size
        self._n_seen = 0
        self._sum = 0.0
        self._max = 0.0
        # Cheap counters the manifest's cadence_quality consumes
        self._gaps_over_2x_nominal = 0
        self._gaps_over_5x_nominal = 0
        # Random state (deterministic seed for reproducibility — the
        # reservoir biases are statistical, not ordering-dependent).
        # Use a fresh local Random so we don't leak global rng state.
        import random
        self._rng = random.Random(0xC0DECAFE)

    def add(self, gap_seconds: float, *, nominal_interval_s: float = 1.0) -> None:
        if gap_seconds <= 0.0:
            # The first sample's gap is 0 — drop it from the
            # statistics (the v1.2 _summarise_cadence does the same).
            return
        self._n_seen += 1
        self._sum += gap_seconds
        if gap_seconds > self._max:
            self._max = gap_seconds
        if gap_seconds >= 2.0 * nominal_interval_s:
            self._gaps_over_2x_nominal += 1
        if gap_seconds >= 5.0 * nominal_interval_s:
            self._gaps_over_5x_nominal += 1
        # Reservoir sampling.
        if len(self._reservoir) < self._reservoir_size:
            self._reservoir.append(gap_seconds)
        else:
            j = self._rng.randint(0, self._n_seen - 1)
            if j < self._reservoir_size:
                self._reservoir[j] = gap_seconds

    def percentile(self, q: float) -> float:
        """Estimate percentile q in [0, 100] from the reservoir."""
        if not self._reservoir:
            return 0.0
        s = sorted(self._reservoir)
        if q <= 0:
            return s[0]
        if q >= 100:
            return s[-1]
        rank = (q / 100.0) * (len(s) - 1)
        lo = int(rank)
        hi = min(lo + 1, len(s) - 1)
        frac = rank - lo
        return s[lo] + frac * (s[hi] - s[lo])

    @property
    def n(self) -> int:
        return self._n_seen

    @property
    def max(self) -> float:
        return self._max

    @property
    def mean(self) -> float:
        return self._sum / self._n_seen if self._n_seen else 0.0

    @property
    def gaps_over_2x_nominal(self) -> int:
        return self._gaps_over_2x_nominal

    @property
    def gaps_over_5x_nominal(self) -> int:
        return self._gaps_over_5x_nominal
