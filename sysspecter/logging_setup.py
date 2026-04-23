"""Logging helpers. Each subsystem gets its own rotated log file plus stderr mirror.

Files rotate at 5 MB and keep 3 generations so a 24-hour run can't fill
the disk with a single unbounded log.
"""

from __future__ import annotations

import logging
import logging.handlers
import sys

_INITIALIZED: set[str] = set()

_MAX_BYTES = 5 * 1024 * 1024   # 5 MB per log file
_BACKUP_COUNT = 3               # keep collector.log.1 .. .3


def get_logger(
    name: str,
    log_file: str | None = None,
    level: int = logging.INFO,
    *,
    max_bytes: int = _MAX_BYTES,
    backup_count: int = _BACKUP_COUNT,
) -> logging.Logger:
    logger = logging.getLogger(name)
    if name in _INITIALIZED:
        return logger

    logger.setLevel(level)
    logger.propagate = False
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")

    if log_file is not None:
        fh = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
        fh.setFormatter(fmt)
        fh.setLevel(level)
        logger.addHandler(fh)

    sh = logging.StreamHandler(sys.stderr)
    sh.setFormatter(fmt)
    sh.setLevel(logging.WARNING)
    logger.addHandler(sh)

    _INITIALIZED.add(name)
    return logger
