import math

from agent_privilege.evaluation.statistics import bootstrap_ci, exact_mcnemar, percentile, wilson


def test_wilson_known_values():
    lo, hi = wilson(0, 10)
    assert lo == 0.0 and math.isclose(hi, 0.2775, abs_tol=1e-3)
    lo, hi = wilson(5, 10)
    assert math.isclose(lo, 0.2366, abs_tol=1e-3) and math.isclose(hi, 0.7634, abs_tol=1e-3)
    assert math.isnan(wilson(0, 0)[0])


def test_mcnemar_exact():
    assert exact_mcnemar(0, 0) == 1.0
    assert exact_mcnemar(5, 5) == 1.0
    assert math.isclose(exact_mcnemar(4, 0), 0.125)
    assert exact_mcnemar(40, 0) < 1e-10


def test_bootstrap_deterministic_and_brackets():
    v = list(range(1, 201))
    a = bootstrap_ci(v, lambda x: float(x.mean()), seed=1, n_boot=200)
    assert a == bootstrap_ci(v, lambda x: float(x.mean()), seed=1, n_boot=200)
    assert a[0] < 100.5 < a[1]
    assert percentile([1, 2, 3, 4], 50) == 2.5
