"""Delegation: child authority = intersection(parent intent, child request, policy ceiling).
Any request exceeding the parent in any dimension is an amplification attempt and is denied
(not silently clipped). Omitted request dimensions mean 'none'."""
from __future__ import annotations

from decimal import Decimal, InvalidOperation
from typing import Any

LIST_DIMS = ("tools", "accounts", "destinations")


def _limit_cents(value: Any) -> int:
    """Non-negative limit in cents (zero allowed, unlike a transfer amount). Raises ValueError."""
    if isinstance(value, bool) or isinstance(value, float) or not isinstance(value, (str, int)):
        raise ValueError("limit must be str/int")
    try:
        d = Decimal(str(value))
    except InvalidOperation as e:
        raise ValueError("unparseable") from e
    c = d * 100
    if not d.is_finite() or d < 0 or c != c.to_integral_value():
        raise ValueError("invalid limit")
    return int(c)


def amplification(parent: dict[str, Any], requested: dict[str, Any]) -> list[str]:
    """Return list of dimensions in which `requested` exceeds `parent` (pure)."""
    out: list[str] = []
    for d in LIST_DIMS:
        req = requested.get(d, [])
        if not isinstance(req, list) or not set(map(str, req)) <= set(parent[d]):
            out.append(d)
    if "max_amount" in requested:
        try:
            if _limit_cents(requested["max_amount"]) > parent["max_amount_cents"]:
                out.append("max_amount")
        except ValueError:
            out.append("max_amount")
    return out


def attenuate(parent: dict[str, Any], requested: dict[str, Any]) -> dict[str, Any]:
    child = dict(parent)
    for d in LIST_DIMS:
        child[d] = sorted(set(parent[d]) & set(map(str, requested.get(d, []))))
    cents = 0
    if "max_amount" in requested:
        cents = min(parent["max_amount_cents"], _limit_cents(requested["max_amount"]))
    child["max_amount_cents"] = cents
    child["max_total_cents"] = min(parent["max_total_cents"], cents)
    return child
