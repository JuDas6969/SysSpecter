# ADR 0005 — Sanitizer uses rule-based redaction with a self-verify pass

**Status:** Accepted (v1.0.0)

## Context

When a customer forwards a report to a vendor or a support engineer,
the raw run contains:
- Hostname + FQDN
- BIOS / disk / baseboard serial numbers
- Windows username (as path fragments and in process trees)
- Installed-program inventory
- Running process command lines (future: not yet captured verbatim)

These identifiers may be PII / infrastructure-sensitive / regulated
(DSGVO, internal security policies). A "sanitize → verify" flow
produces a de-identified sibling folder that can be shipped safely.

## Decision

Two modules:

1. [sysspecter/sanitizer.py](sysspecter/sanitizer.py) collects the
   identifier set from manifest + static_snapshot, walks the
   copied run folder, and replaces every occurrence in JSON and
   string-like CSV cells.
2. [sysspecter/sanitizer_verify.py](sysspecter/sanitizer_verify.py)
   RE-reads the sanitized copy and scans for any leftover occurrence
   of the (pre-redaction) identifiers, returning concrete
   `LeakHit(file, location, snippet)` records.

The CLI `sysspecter sanitize` calls `sanitize_run()` and then
`verify()`, printing a warning (but not failing) if the verifier
finds leaks. The test-suite has a positive case (`verify()` finds 0
hits after `sanitize_run()`) and a negative case (`verify()` finds
hits before `sanitize_run()`).

## Consequences

**Pro**
- Separation of concerns: the sanitizer does the rewrite, the
  verifier is an independent audit step.
- The verifier catches regressions: if a future change adds a CSV
  column that the sanitizer missed, the test fails.
- Short identifiers (< 4 chars) are skipped in the verifier to avoid
  false positives like "PC" matching "PCI" or "PCIe".

**Contra**
- Pure-string redaction is inherently leaky if the sanitizer misses
  a field. The verifier catches KNOWN identifiers but not derived
  secrets (e.g. a hostname that got hashed into a GUID elsewhere).
- API keys / passwords baked into process-cmdline strings are NOT
  currently redacted because the collector doesn't persist cmdlines
  yet; the sanitizer's `redact_columns` set includes `cmdline`,
  `image_path`, `exe` ahead of time so when the collector starts
  writing them, they are caught automatically.

## Alternatives considered

- Differential-privacy-style hashing (replace hostname with a
  deterministic hash) — rejected: undoes comparability between
  sanitized runs and loses the "show the redacted-ness" signal.
- Whitelist-of-columns approach (only include known-safe columns) —
  rejected: too brittle, fails every time a new column ships.
