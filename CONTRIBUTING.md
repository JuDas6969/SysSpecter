# Contributing to SysSpecter

Thanks for taking the time to improve SysSpecter. Every fix, test, or
documentation tweak helps.

## Quick start (60 seconds)

```
git clone https://github.com/JuDas6969/SysSpecter.git
cd SysSpecter
install.bat
.\.venv\Scripts\activate
pytest -q
```

That's it — you now have a working dev environment with all pinned
dependencies and can run the full test suite.

## Development workflow

1. **Branch** off `main`: `git switch -c fix/<short-description>`.
2. **Write a test first** if you can — the golden HTML regression test
   and the schema-migration test fire on almost every template change.
3. **Format + lint**: `ruff check sysspecter tests && ruff format
   sysspecter tests`. The pre-commit hook (see below) runs this
   automatically.
4. **Run tests**: `pytest -q`. Keep it green — CI gates releases on it.
5. **Build the EXE** if you changed anything under `sysspecter/gui/` or
   `sysspecter/reporter/templates/`: `build_exe.bat` then double-click
   `dist/SysSpecter.exe` to smoke-test the packaged version.
6. **Commit** with a message that explains *why*, not just *what*. The
   existing git log is a good style reference.
7. **Open a PR** against `main`. CI will run tests on Python 3.12 + 3.13
   plus `pip-audit` and `bandit`.

## Pre-commit hooks

Install once:

```
pip install pre-commit
pre-commit install
```

On every `git commit`, Ruff auto-formats + lints the changed files.

## Coding guidelines

- **Type hints everywhere.** `from __future__ import annotations` at the
  top of every module; parameters + return types on every function.
- **No silent `except`** unless you attach a one-line comment explaining
  *why* the failure is irrelevant. Default pattern:

  ```python
  try:
      ...
  except Exception:
      _log.debug("xyz failed", exc_info=True)
  ```

- **One module, one responsibility.** If a file grows past ~300 lines,
  think about extracting helpers.
- **Tests are colocated in `tests/`** with one test file per module
  under `sysspecter/`. New modules need at least a smoke test.
- **No new GUI tests**, sadly — Tkinter doesn't unit-test well. Manual
  smoke-check after any GUI change is enough.
- **ADR for architectural decisions.** If you change how two modules
  talk to each other, add a short ADR under `docs/adr/`.

## Commit-message style

```
<area>: <short imperative summary, ≤ 72 chars>

Longer explanation if the *why* needs it. Wrap at 72 cols. Reference
issues or PRs with `#123`.
```

Examples:

- `collector: log debug on cpu_freq unavailable instead of swallowing`
- `gui: drop redundant pady on Runs-tab command-output label`

## Release process

Tag-driven. A maintainer:

1. Bumps `sysspecter/__init__.py:__version__`.
2. Updates `CHANGELOG.md` under a new `## [x.y.z] - YYYY-MM-DD` heading.
3. Commits, tags `git tag -a vX.Y.Z -m "vX.Y.Z"`, pushes with
   `git push origin vX.Y.Z`.
4. GitHub Actions (`release.yml`) does the rest: tests, EXE build, SBOM,
   SHA-256, GitHub Release.

See [BUILDING.md](BUILDING.md) for signing + reproducibility details.

## Questions?

Open a GitHub Discussion or ping @JuDas6969 on the issue tracker.
