"""Small, dependency-light statistics: Wilson intervals, bootstrap percentile CIs, exact McNemar."""
from __future__ import annotations

import math
from collections.abc import Sequence

import numpy as np


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def bootstrap_ci(values: Sequence[float], stat, *, seed: int, n_boot: int = 1000,
                 alpha: float = 0.05) -> tuple[float, float]:
    a = np.asarray(values, dtype=float)
    if a.size == 0:
        return (float("nan"), float("nan"))
    rng = np.random.default_rng(seed)
    idx = rng.integers(0, a.size, size=(n_boot, a.size))
    boots = np.array([stat(a[i]) for i in idx])
    return (float(np.quantile(boots, alpha / 2)), float(np.quantile(boots, 1 - alpha / 2)))


def percentile(values: Sequence[float], q: float) -> float:
    return float(np.percentile(np.asarray(values, dtype=float), q)) if len(values) else float("nan")


def exact_mcnemar(b: int, c: int) -> float:
    """Two-sided exact binomial p-value on discordant pairs (b, c)."""
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    tail = sum(math.comb(n, i) for i in range(k + 1)) / 2**n
    return min(1.0, 2 * tail)


MIN_SAMPLES_FOR_P99 = 1000
