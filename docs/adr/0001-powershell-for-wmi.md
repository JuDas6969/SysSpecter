# ADR 0001 — Use PowerShell for WMI queries, not the `wmi` Python package

**Status:** Accepted (v1.0.0)

## Context

The static snapshot needs data from Windows Management Instrumentation
(WMI) — BIOS info, physical disks, GPU adapters, Defender status,
installed programs, firewall profiles.

Two options:
1. The `wmi` Python package (thin wrapper around `pywin32`).
2. `powershell.exe -Command "Get-CimInstance ... | ConvertTo-Json"`
   piped through `subprocess`.

## Decision

We call PowerShell via `subprocess.run` ([winutil.py::run_ps_json](sysspecter/winutil.py)).

## Consequences

**Pro**
- Zero extra dependency besides `pywin32` (already needed for
  `ctypes.windll.shell32.IsUserAnAdmin`).
- Survives WMI provider quirks gracefully — a failed PowerShell call
  returns `None` and the sampler logs + degrades; the `wmi` package
  raises in-process on the same condition.
- Works identically whether the user is admin or not; the `wmi`
  package needs elevated COM permissions on some Windows editions.
- PowerShell is present on every supported Windows build (Server 2016+
  / Windows 10+).

**Contra**
- Per-query startup cost ~150 ms (PowerShell process spawn). Total
  overhead in a run is ~1.5 s on startup; acceptable because static
  queries happen only once.
- `ConvertTo-Json -Depth 5` may truncate very deep objects. Mitigated
  by requesting specific `Select-Object` fields.
- Locale-specific output (deutsche WMI-Werte) requires explicit
  handling in the analyzer; not currently a problem because we read
  numeric / boolean fields predominantly.

## Alternatives considered

- Embedding `wmi` → larger EXE, broken behaviour under some WMI
  configurations.
- Direct `ctypes` calls into `wbemuuid.dll` → correct but 10× the
  code for the same data.
