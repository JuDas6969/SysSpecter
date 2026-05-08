# ADR 0006 — Cross-platform abstraction layer (POSIX-ready, Windows-shipped)

**Status:** Accepted (v1.1.0+)
**Field-review item:** C5

## Context

SysSpecter is Windows-only by design today. Every collector reaches
into Win32 directly: `ctypes.windll.shell32.IsUserAnAdmin()` is called
in four files, every static-snapshot field comes from
`Get-CimInstance`, ETW is tied to `logman.exe`, and machine_id pulls
the SMBIOS UUID via PowerShell. Functional, fast to ship, but locks
out three real customer environments:

- Engineering teams running mixed Windows / Linux fleets (CI, build
  servers, network appliances).
- Data-science groups on macOS workstations.
- Even Windows-first IT shops have their CI on Linux.

The field review recommended that even if the first ship stays
Windows-only, OS-specific calls should live behind a clean
abstraction:

> Hard to retrofit later if the architecture assumes Win32 throughout.

The cost of a half-baked abstraction is high too — every line of
abstraction that doesn't match the eventual Linux / macOS adapter is
worse than no abstraction at all. So we pick the smallest abstraction
that catches the architectural lock-in and leaves the implementation
choice for later.

## Decision

Introduce a single ABC `sysspecter.platforms.Platform` covering the
methods that have a real cross-platform equivalent today:

```text
is_admin                       # Windows: shell32, POSIX: geteuid
machine_id_smbios_uuid         # Windows: WMI, POSIX: dmi/ioreg
machine_id_machine_sid         # Windows-only concept
machine_id_macs                # cross-platform via psutil
```

Concrete implementations live in `platforms/windows.py` (delegating to
existing helpers) and `platforms/posix.py` (stub with stdlib-friendly
defaults that return `None` for OS-specific values).

A factory `platforms.platform()` selects the implementation from
`sys.platform` and caches it. Tests can inject via
`set_platform(custom_impl)`.

The four duplicated `IsUserAnAdmin()` blocks in `manifest.py`,
`doctor.py`, `gui/components/status_bar.py`, `gui/tab_monitor.py` are
replaced with calls through the ABC. `compute_machine_id()` pulls its
three primitives through the ABC. Everything else (PowerShell-WMI
snapshot, ETW, eventlog) stays Windows-direct for now — those are
genuine collector-tier rewrites and belong in their own ADRs when a
POSIX collector lands.

## Consequences

**Pro**

- Single place to fix admin-detection across the whole codebase.
- Future Linux / macOS implementation is a new file under `platforms/`
  rather than a search-and-replace through every collector.
- Tests can inject a fake platform without monkey-patching `ctypes`.
- `machine_id` works on Linux today (MAC + hostname fallback) without
  any special-casing — the resolver was already tier-based.

**Contra**

- Two extra layers of indirection for the admin check (negligible
  cost, ~µs).
- The abstraction surface is intentionally minimal — most collectors
  still don't go through it. A future Linux collector tier still
  needs its own ADR for the sampler ABC.

## Alternatives considered

- **`os.platform`-conditional code in every collector** — what the
  legacy code does. Works, but four duplicate IsUserAnAdmin blocks
  show how it drifts.
- **Strategy pattern per collector** (sampler, eventlog, etc., each
  has its own `WindowsX` / `LinuxX` implementations with ABCs) —
  too big for the current shipped surface; defer to per-collector
  ADRs when each adapter is needed.
- **Runtime feature-flags read from manifest.platform** — opaque,
  doesn't help test mocking, makes static analysis harder.

## Validation

- `tests/test_platforms.py` covers factory caching, override, reset,
  and that `WindowsPlatform` delegates to the existing helpers
  unchanged.
- The 19 existing M5 tests still pass without modification —
  `compute_machine_id` now flows through the ABC but tests inject the
  test inputs at the same `_smbios_uuid` / `_machine_sid` / `_macs`
  hook points.
- Existing Windows-only tests are unaffected (no behaviour change in
  the Windows path).

## Future work (out of scope here)

- Sampler ABC (collector tier) for Linux eBPF / perf_events.
- Static-snapshot ABC (replace WMI calls with platform-specific
  collectors).
- ETW abstraction → kernel ftrace / dtrace bridge.
- Per-collector ADRs as each new adapter lands.

These are months of work each and live behind their own ADRs once
needed.
