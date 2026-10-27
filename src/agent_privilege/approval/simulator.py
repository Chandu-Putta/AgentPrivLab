"""Reviewer models. SYNTHETIC: parameterised reviewer behaviour, NOT measured human behaviour.

- scripted: follows the decision written in the scenario fixture (idealised reviewer).
- rubber_stamp: approves everything (worst-case reviewer).
- always_reject: rejects everything.
"""
from __future__ import annotations

import random
from dataclasses import dataclass


def reviewer_decision(mode: str, scripted: str | None) -> bool:
    if mode == "rubber_stamp":
        return True
    if mode == "always_reject":
        return False
    return scripted == "approve"


@dataclass
class FatigueModel:
    """Error rate rises with the number of approvals a reviewer has handled in a shift:
    p_err(n) = min(cap, base + slope * n). All parameters are ASSUMPTIONS under sweep."""

    base: float = 0.02
    slope: float = 0.0005
    cap: float = 0.5

    def p_err(self, n: int) -> float:
        return min(self.cap, self.base + self.slope * n)


def simulate_shift(rng: random.Random, n_requests: int, malicious_frac: float, model: FatigueModel,
                   ) -> dict[str, int]:
    """Reviewer handles n sequential requests; errors flip the correct decision."""
    mal_total = mal_approved = leg_total = leg_rejected = 0
    for n in range(n_requests):
        malicious = rng.random() < malicious_frac
        err = rng.random() < model.p_err(n)
        approved = (malicious and err) or (not malicious and not err)
        if malicious:
            mal_total += 1
            mal_approved += approved
        else:
            leg_total += 1
            leg_rejected += (not approved)
    return {"mal_total": mal_total, "mal_approved": mal_approved,
            "leg_total": leg_total, "leg_rejected": leg_rejected}
