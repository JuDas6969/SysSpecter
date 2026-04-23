# Security Policy

## Reporting a Vulnerability

If you discover a security issue in SysSpecter, please **do not** open a
public GitHub issue. Instead, email:

**david.juriga@ktm.com** (PGP key available on request)

Include:

- A description of the issue.
- Steps to reproduce (commit hash / version tag / OS version).
- Impact assessment (data exposure, privilege escalation, remote
  execution, etc.).
- Any proof-of-concept code.

You should receive an acknowledgement within **7 calendar days**. If you
don't, please follow up — your email may have been filtered.

## Supported Versions

SysSpecter follows Semantic Versioning. Only the latest **minor** release
receives security updates.

| Version | Supported |
| ------- | --------- |
| 1.x     | Yes       |
| 0.x     | No        |

## Disclosure Policy

- We target a fix within **30 days** of confirmation for high-severity
  issues, **90 days** for medium / low.
- Once a patched release ships, we publish a CVE (via MITRE CNA) and
  credit the reporter unless they prefer to stay anonymous.
- We ask for a **90-day embargo** before public disclosure so users can
  update.

## Scope

In scope:

- Arbitrary code execution when running the shipped EXE.
- Privilege escalation when the tool is run without admin rights.
- Data leakage from `sanitize` output (identifiers that should have been
  redacted but weren't).
- Supply-chain issues in the build pipeline.

Out of scope:

- Crashes that leave no externally observable side-effects.
- Issues in third-party collectors that can only be triggered with full
  admin rights (those are platform-level issues).
- Social-engineering attacks against a user who voluntarily runs an
  unverified build.

## Hardening the Build

See [BUILDING.md](BUILDING.md) for the release hardening roadmap:

- CI runs `pip-audit` (dependency CVE scan) + `bandit` (SAST) on every PR.
- Every release publishes `SysSpecter.exe.sha256`. Verify before running.
- Every release publishes a CycloneDX SBOM (`SysSpecter.sbom.json`).
- Code-signing (Authenticode OV/EV) is planned for v1.1.
- Reproducible builds (`SOURCE_DATE_EPOCH`) are partially implemented.
