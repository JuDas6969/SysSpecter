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


def linear_regression_r2(xs: list[float], ys: list[float]) -> float | None:
    """Coefficient of determination R^2 for the best-fit line. In [0, 1]."""
    n = len(xs)
    if n < 2 or n != len(ys):
        return None
    mean_x = sum(xs) / n
    mean_y = sum(ys) / n
    num = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys))
    den_x = sum((x - mean_x) ** 2 for x in xs)
    den_y = sum((y - mean_y) ** 2 for y in ys)
    if den_x == 0 or den_y == 0:
        return None
    slope = num / den_x
    intercept = mean_y - slope * mean_x
    ss_res = sum((y - (slope * x + intercept)) ** 2 for x, y in zip(xs, ys))
    ss_tot = den_y
    return max(0.0, 1.0 - ss_res / ss_tot)


def monotonic_nondecreasing_ratio(values: list[float]) -> float:
    """Fraction of adjacent pairs where v[i+1] >= v[i]. 1.0 = strictly monotonic growth."""
    if len(values) < 2:
        return 0.0
    pairs = len(values) - 1
    ok = sum(1 for i in range(pairs) if values[i + 1] >= values[i])
    return ok / pairs


def plateau_fraction(values: list[float], tolerance_ratio: float = 0.02) -> float:
    """Fraction of the series, measured from the end, whose values stay within
    `tolerance_ratio` of the final value. High plateau => not a leak; growth stopped."""
    if len(values) < 2:
        return 0.0
    final = values[-1]
    if final <= 0:
        return 0.0
    tol = abs(final) * tolerance_ratio
    n = 0
    for v in reversed(values):
        if abs(v - final) <= tol:
            n += 1
        else:
            break
    return n / len(values)


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
