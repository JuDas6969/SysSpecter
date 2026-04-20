"""Logging helpers. Each subsystem gets its own log file plus stderr mirror."""

from __future__ import annotations

import logging
import sys

_INITIALIZED: set[str] = set()


def get_logger(name: str, log_file: str | None = None, level: int = logging.INFO) -> logging.Logger:
    logger = logging.getLogger(name)
    if name in _INITIALIZED:
        return logger

    logger.setLevel(level)
    logger.propagate = False
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")

    if log_file is not None:
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setFormatter(fmt)
        fh.setLevel(level)
        logger.addHandler(fh)

    sh = logging.StreamHandler(sys.stderr)
    sh.setFormatter(fmt)
    sh.setLevel(logging.WARNING)
    logger.addHandler(sh)

    _INITIALIZED.add(name)
    return logger
