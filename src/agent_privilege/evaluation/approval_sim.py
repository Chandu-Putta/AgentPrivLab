"""Approval-fatigue SENSITIVITY simulation. SYNTHETIC reviewer model, not measured humans.

Question answered: given a stream of escalations of which a fraction `m` are malicious, how do
a reviewer's base error rate and fatigue slope change the expected number of malicious
approvals leaking through and legitimate approvals wrongly rejected?"""
from __future__ import annotations

import itertools
import random
from typing import Any

from ..approval.simulator import FatigueModel, simulate_shift
from .statistics import wilson


def run_sweep(*, seed: int, shifts: int = 200, base=(0.01, 0.05, 0.10), slope=(0.0, 0.0005, 0.002),
              mal_frac=(0.01, 0.05, 0.20), lengths=(50, 200, 1000)) -> list[dict[str, Any]]:
    rows = []
    for b, sl, m, n in itertools.product(base, slope, mal_frac, lengths):
        rng = random.Random(f"{seed}|{b}|{sl}|{m}|{n}")
        tot = dict(mal_total=0, mal_approved=0, leg_total=0, leg_rejected=0)
        for _ in range(shifts):
            r = simulate_shift(rng, n, m, FatigueModel(base=b, slope=sl))
            for k in tot:
                tot[k] += r[k]
        lo, hi = wilson(tot["mal_approved"], tot["mal_total"])
        rows.append({"base_error": b, "fatigue_slope": sl, "malicious_fraction": m, "shift_length": n,
                     "shifts": shifts, **tot,
                     "false_approval_rate": tot["mal_approved"] / max(1, tot["mal_total"]),
                     "false_approval_ci_lo": lo, "false_approval_ci_hi": hi,
                     "false_reject_rate": tot["leg_rejected"] / max(1, tot["leg_total"]),
                     "leaked_per_1000_escalations": 1000 * m * tot["mal_approved"] / max(1, tot["mal_total"]),
                     "assumption_label": "synthetic_reviewer_model_not_human_data"})
    return rows
