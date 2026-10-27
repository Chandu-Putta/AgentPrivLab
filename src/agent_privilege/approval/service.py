"""Approval workflow: approvals are bound to the exact canonical request hash, expire, and are
single use. Approval is only ever consulted for in-policy actions (never overrides DENY)."""
from __future__ import annotations

from dataclasses import dataclass

from ..clock import Clock


@dataclass
class Approval:
    approval_id: str
    request_hash: str
    approver: str
    status: str  # approved | rejected
    exp_ms: int
    used: bool = False


class ApprovalService:
    def __init__(self, clock: Clock, ttl_s: int = 300) -> None:
        self.clock, self.ttl_s = clock, ttl_s
        self._items: dict[str, Approval] = {}
        self._n = 0

    def record(self, request_hash: str, approver: str, approved: bool) -> Approval:
        self._n += 1
        a = Approval(f"apr-{self._n:05d}", request_hash, approver,
                     "approved" if approved else "rejected",
                     int(self.clock.now() * 1000) + self.ttl_s * 1000)
        self._items[a.approval_id] = a
        return a

    def validate(self, approval_id: str | None, request_hash: str) -> dict:
        """Return {'presented','valid','reason','bound_hash'}; does not consume."""
        if not approval_id:
            return {"presented": False, "valid": False, "reason": "none", "bound_hash": None}
        a = self._items.get(approval_id)
        if a is None:
            return {"presented": True, "valid": False, "reason": "unknown_approval", "bound_hash": None}
        bh = a.request_hash
        if a.status != "approved":
            r = "approval_rejected"
        elif a.used:
            r = "approval_used"
        elif int(self.clock.now() * 1000) > a.exp_ms:
            r = "approval_expired"
        elif a.request_hash != request_hash:
            r = "approval_hash_mismatch"
        else:
            r = "ok"
        return {"presented": True, "valid": r == "ok", "reason": r, "bound_hash": bh}

    def consume(self, approval_id: str) -> None:
        self._items[approval_id].used = True
