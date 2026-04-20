"""Small statistics helpers used across detectors."""

from __future__ import annotations

from typing import Iterable


def percentile(values: list[float], pct: float) -> float | None:
    if not values:
        return None
    s = sorted(values)
    if len(s) == 1:
        return s[0]
    k = (len(s) - 1) * (pct / 100.0)
    f = int(k)
    c = min(f + 1, len(s) - 1)
    if f == c:
        return s[f]
    return s[f] + (s[c] - s[f]) * (k - f)


def moving_average(values: list[float], window: int) -> list[float]:
    if not values or window <= 1:
        return list(values)
    out: list[float] = []
    run_sum = 0.0
    from collections import deque
    q: deque = deque()
    for v in values:
        q.append(v)
        run_sum += v
        if len(q) > window:
            run_sum -= q.popleft()
        out.append(run_sum / len(q))
    return out


def linear_regression_slope(xs: list[float], ys: list[float]) -> float | None:
    """Slope of y = mx + b. Returns None if degenerate."""
    n = len(xs)
    if n < 2 or n != len(ys):
        return None
    mean_x = sum(xs) / n
    mean_y = sum(ys) / n
    num = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys))
    den = sum((x - mean_x) ** 2 for x in xs)
    if den == 0:
        return None
    return num / den


def mean(values: Iterable[float]) -> float | None:
    lst = list(values)
    if not lst:
        return None
    return sum(lst) / len(lst)


def max_opt(values: Iterable[float]) -> float | None:
    lst = list(values)
    if not lst:
        return None
    return max(lst)


def sustained_windows(
    values: list[float],
    threshold: float,
    min_duration_samples: int,
) -> list[tuple[int, int]]:
    """Return (start_idx, end_idx_inclusive) for runs where values >= threshold
    lasting at least min_duration_samples consecutive samples."""
    windows: list[tuple[int, int]] = []
    start: int | None = None
    for i, v in enumerate(values):
        if v is not None and v >= threshold:
            if start is None:
                start = i
        else:
            if start is not None and i - start >= min_duration_samples:
                windows.append((start, i - 1))
            start = None
    if start is not None and len(values) - start >= min_duration_samples:
        windows.append((start, len(values) - 1))
    return windows


def merge_windows(windows: list[tuple[int, int]], gap: int) -> list[tuple[int, int]]:
    if not windows:
        return []
    merged = [windows[0]]
    for s, e in windows[1:]:
        ps, pe = merged[-1]
        if s - pe <= gap:
            merged[-1] = (ps, max(pe, e))
        else:
            merged.append((s, e))
    return merged
