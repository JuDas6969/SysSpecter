"""Fleet aggregation (Field-review M3).

Where `compare` answers "how do these N runs relate?", `aggregate`
answers "across hundreds of runs in a fleet, which machines are
anomalous and how is the fleet drifting?". The pieces:

    loader      → walk a runs/ tree, build per-run summaries
    aggregate   → fleet statistics (mean / p50 / p95 / std per metric)
                  + per-machine grouping and longitudinal sort
    outliers    → z-score detection per machine vs fleet
    drift       → first-run vs last-run delta per machine
    report      → HTML fleet view
"""

from __future__ import annotations

from .aggregate import run_aggregate

__all__ = ["run_aggregate"]
