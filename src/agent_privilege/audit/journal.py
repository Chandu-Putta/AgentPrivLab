"""Append-only JSONL audit journal with SHA-256 hash chaining.

Tamper-EVIDENT only: an attacker who can rewrite the whole file and recompute the chain
is not detected. Anchor the head hash externally for stronger guarantees.
"""
from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

from ..gateway.canonicalize import canonical_json, sha256_hex

GENESIS = "0" * 64

REQUIRED_FIELDS = (
    "ts", "run_id", "trace_id", "scenario_id", "agent_id", "parent_agent_id", "tenant", "task_id",
    "grant_id", "grant_hash", "tool", "resource_ids", "params_hash", "request_hash",
    "policy_id", "policy_version", "policy_hash", "policy_inputs", "decision", "reasons",
    "approval_id", "approval_status", "approval_bound_hash", "delegation_lineage",
    "outcome", "side_effect_ref", "latency_us", "correlation_id",
)


class AuditJournal:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path
        self.records: list[dict[str, Any]] = []
        self._head = GENESIS
        self._lock = threading.Lock()
        if path is not None:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("")

    @staticmethod
    def entry_hash(prev: str, body: dict[str, Any]) -> str:
        return sha256_hex(prev + canonical_json(body))

    def append(self, **fields: Any) -> dict[str, Any]:
        missing = [f for f in REQUIRED_FIELDS if f not in fields]
        if missing:
            raise ValueError(f"audit record missing fields: {missing}")
        with self._lock:
            body = {k: fields[k] for k in REQUIRED_FIELDS}
            rec = {**body, "seq": len(self.records), "prev_hash": self._head}
            rec["hash"] = self.entry_hash(self._head, {k: v for k, v in rec.items() if k != "hash"})
            self._head = rec["hash"]
            self.records.append(rec)
            if self.path is not None:
                with self.path.open("a") as f:
                    f.write(json.dumps(rec, sort_keys=True) + "\n")
            return rec

    @property
    def head(self) -> str:
        return self._head

    def audit_bytes(self) -> int:
        return sum(len(json.dumps(r, sort_keys=True)) + 1 for r in self.records)
