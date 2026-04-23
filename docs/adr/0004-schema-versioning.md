# ADR 0004 — Versioning policy for the JSON artifacts

**Status:** Accepted (v1.0.0, schema_version=2)

## Context

Every finished run emits a stack of JSON files:

| File | Contract |
|---|---|
| `manifest.json` | run metadata — **externally referenced** (tools, scripts, audits) |
| `findings.json` | analyzer output — internal to the reporter |
| `scores.json` | scoring pipeline output — consumed by reports + compare |
| `phases.json` | splitter output — consumed by the overview page |
| `comparison_findings.json` | compare tool output |

These grow in shape over time (e.g. `sysspecter_version` was added in
v1.0.0, `collector_degraded` in v1.0.1, `window_start_seconds` in the
trim feature). Old runs need to keep opening in newer tools — a
1-year-old manifest.json must still render.

## Decision

1. **`manifest.json` carries a `schema_version` integer** — currently
   `2`. Older v1 runs (no `sysspecter_version`, no
   `collector_degraded`, no `window_start_seconds`) remain valid.
2. **Other artifacts inherit the manifest's `schema_version`** — no
   per-file version numbers. They change together in lockstep.
3. **Tolerant validation** via pydantic models in
   [sysspecter/domain/schemas.py](sysspecter/domain/schemas.py):
   - Every new-in-v2 field is `Optional` so v1 documents validate.
   - `extra="allow"` so future-version documents are not rejected;
     unknown keys are stored on the model.
4. **Bump rules**
   - **Patch-bump of `sysspecter_version`**: no schema change.
   - **Minor-bump**: new optional fields allowed, `schema_version`
     stays.
   - **Major-bump of `sysspecter_version` = MAJOR-bump of
     `schema_version`**: removed or renamed fields. Old runs get a
     migration path (loader tolerates or the CLI offers `sysspecter
     migrate-runs`, to be added when a major bump happens).

## Consequences

**Pro**
- Every tool in the pipeline can be written against a single
  pydantic schema and stay honest about what it expects.
- v1 runs in the wild remain loadable without bespoke code.
- Test fixture `test_schema_migration.py` proves the tolerance and
  locks `CURRENT_SCHEMA_VERSION` against accidental bumps.

**Contra**
- Pydantic adds ~2 MB to the frozen EXE.
- "Tolerant validation" hides typos — a field named `tagz` on a bad
  writer would silently become an extra key and never fail a test.
  Mitigation: CI runs the schema tests, which include a positive
  check for the canonical keys.

## Migration plan (when schema_version=3 lands)

1. Bump `CURRENT_SCHEMA_VERSION` + update the golden fixture.
2. Add a `migrate_v2_to_v3(raw_manifest: dict) -> dict` helper.
3. `Run.manifest` auto-migrates in the getter; existing reports
   remain byte-stable unless the test regenerates them.
