"""Decorator for collector functions that may fail non-fatally.

Usage:

    from .safe_collect import safe_collect

    @safe_collect("gpu", fallback=[])
    def collect_gpu_snapshot(...):
        ...

When the wrapped function raises, the exception is logged at DEBUG,
`mark_degraded(manifest_path, name, reason)` is called on the thread-
local manifest path, and `fallback` is returned instead. The caller
sees a successful return value (e.g. empty list) and keeps running.

Callers set the manifest path once per run with `set_manifest_path()`.
This is a light-weight alternative to threading it through every
sampler signature.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from functools import wraps
from typing import Any, TypeVar

T = TypeVar("T")

_manifest_path: threading.local = threading.local()


def set_manifest_path(path: str | None) -> None:
    """Set the manifest path for the current thread. Pass None to clear."""
    _manifest_path.path = path


def get_manifest_path() -> str | None:
    return getattr(_manifest_path, "path", None)


def safe_collect(
    name: str,
    *,
    fallback: Any = None,
    log_level: int = logging.DEBUG,
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """Wrap a collector callable.

    Parameters
    ----------
    name:
        Short identifier that lands in `manifest.collector_degraded[name]`
        and in the log line. Pick something stable (e.g. "gpu",
        "network_sampler", "static.wmi.cpu").
    fallback:
        Returned when the wrapped callable raises. If callable, it is
        invoked at failure time to produce the value (useful for
        dict/list factories so different call sites get separate
        instances).
    log_level:
        Level at which the exception is recorded. Defaults to DEBUG so
        production logs stay quiet; set to WARNING for investigation.
    """
    def decorator(fn: Callable[..., T]) -> Callable[..., T]:
        logger = logging.getLogger(fn.__module__)

        @wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> T:
            try:
                return fn(*args, **kwargs)
            except Exception as exc:  # noqa: BLE001 — intentional soft-degrade
                logger.log(log_level, "collector %s failed: %s: %s",
                           name, type(exc).__name__, exc, exc_info=False)
                mp = get_manifest_path()
                if mp:
                    try:
                        # local import avoids circular import at module load
                        from .manifest import mark_degraded
                        mark_degraded(mp, name, f"{type(exc).__name__}: {exc}")
                    except Exception:
                        # never let degradation bookkeeping break the collector,
                        # but do leave a trace
                        logger.debug("mark_degraded failed for %s", name,
                                     exc_info=True)
                if callable(fallback):
                    return fallback()  # type: ignore[return-value]
                return fallback  # type: ignore[return-value]
        return wrapper
    return decorator
