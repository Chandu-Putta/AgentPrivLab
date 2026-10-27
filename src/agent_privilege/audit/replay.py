"""Independent deterministic audit replay.

For each JSONL record: (1) schema completeness, (2) hash-chain integrity, (3) re-evaluate the
recorded `policy_inputs` with the policy rebuilt from a snapshotted config whose hash must
equal the recorded `policy_hash`, and compare decision + reasons. Chain verification is
tamper-EVIDENCE only: an attacker who recomputes the whole chain passes (1)-(2) but is still
caught by (3) if they changed a decision without changing its inputs.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..policy.base import config_hash, gateway_precheck
from ..policy.registry import build_strategy
from .journal import GENESIS, REQUIRED_FIELDS, AuditJournal


@dataclass
class ReplayReport:
    total: int = 0
    reproduced: int = 0
    chain_breaks: list[int] = field(default_factory=list)
    incomplete: list[int] = field(default_factory=list)
    mismatches: list[tuple[int, str]] = field(default_factory=list)
    unparseable: list[int] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not (self.chain_breaks or self.incomplete or self.mismatches or self.unparseable) \
            and self.reproduced == self.total

    @property
    def reconstructability(self) -> float:
        return self.reproduced / self.total if self.total else 0.0

    def summary(self) -> dict[str, Any]:
        return {"total": self.total, "reproduced": self.reproduced,
                "reconstructability": self.reconstructability, "chain_breaks": len(self.chain_breaks),
                "incomplete": len(self.incomplete), "mismatches": len(self.mismatches),
                "unparseable": len(self.unparseable), "ok": self.ok}


def load_snapshots(directory: Path) -> dict[str, dict[str, Any]]:
    return {p.stem: json.loads(p.read_text()) for p in sorted(directory.glob("*.json"))}


def _expected(rec: dict[str, Any], snaps: dict[str, dict[str, Any]], cache: dict) -> tuple[str, list[str]]:
    inputs = rec["policy_inputs"]
    if rec["policy_id"] == "gateway":
        r = gateway_precheck(inputs)
        if r is None:
            raise ValueError("gateway deny not reproducible")
        return r.decision.value, list(r.reasons)
    cfg = snaps.get(rec["policy_id"])
    if cfg is None:
        raise ValueError(f"no policy snapshot for {rec['policy_id']}")
    if config_hash(cfg) != rec["policy_hash"]:
        raise ValueError("policy_hash does not match snapshot")
    if rec["reasons"] and rec["reasons"][0] == "policy_unavailable":
        return ("allow" if cfg.get("fail_mode") == "open" else "deny"), list(rec["reasons"])
    st = cache.get(rec["policy_id"]) or cache.setdefault(rec["policy_id"], build_strategy(cfg))
    r = st.policy.evaluate(inputs)
    return r.decision.value, list(r.reasons)


def replay_lines(lines: list[str], snaps: dict[str, dict[str, Any]]) -> ReplayReport:
    rep, prev, cache = ReplayReport(), GENESIS, {}
    for n, line in enumerate(lines):
        rep.total += 1
        try:
            rec = json.loads(line)
        except ValueError:
            rep.unparseable.append(n)
            continue
        missing = [f for f in (*REQUIRED_FIELDS, "seq", "prev_hash", "hash") if f not in rec]
        if missing:
            rep.incomplete.append(n)
            continue
        body = {k: v for k, v in rec.items() if k != "hash"}
        if rec["seq"] != n or rec["prev_hash"] != prev or rec["hash"] != AuditJournal.entry_hash(prev, body):
            rep.chain_breaks.append(n)
        prev = rec["hash"]
        try:
            dec, reasons = _expected(rec, snaps, cache)
        except Exception as e:
            rep.mismatches.append((n, f"cannot_replay:{e}"))
            continue
        if dec != rec["decision"] or reasons != rec["reasons"]:
            rep.mismatches.append((n, f"expected {dec} {reasons}, recorded {rec['decision']} {rec['reasons']}"))
        elif n not in rep.chain_breaks:
            rep.reproduced += 1
    return rep


def replay_file(path: Path, snapshot_dir: Path) -> ReplayReport:
    lines = [ln for ln in path.read_text().splitlines() if ln.strip()]
    return replay_lines(lines, load_snapshots(snapshot_dir))
