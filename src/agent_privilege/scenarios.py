"""Versioned YAML scenario fixtures: loading, template expansion and validation.

Ground truth (`expected_authorization`) is written by hand from the rules in
docs/methodology.md and is never derived from, or edited to flatter, any strategy.
"""
from __future__ import annotations

import json
from pathlib import Path
from string import Template
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .models import Tool

MUTATING = {"transfer_funds", "update_contact", "create_payee", "export_statement"}
BASE_INSTANCES = {f"{t}{c}": (t, c) for t in "ab" for c in (1, 2)}
ENGINE_STRATEGIES = ["external_policy", "external_policy_failopen", "policy_plus_approval",
                     "delegated_attenuation", "delegated_naive"]


class Action(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    type: Literal["tool_call", "request_approval", "event"] = "tool_call"
    agent: str | None = None
    tool: str | None = None
    params: dict[str, Any] = Field(default_factory=dict)
    measured: bool = True
    expansion: bool = False  # delegation scope-expansion attempt
    origin: Literal["scripted_benign", "scripted_malicious"] = "scripted_benign"
    provenance: str = "trusted_task"  # where the proposal text came from (annotation only)
    grant_mode: Literal["normal", "tampered", "none"] = "normal"
    approval_from: str | None = None
    reviewer: Literal["approve", "reject"] | None = None
    fault: Literal["policy_unavailable"] | None = None
    advance_clock_s: int = 0
    event: Literal["revoke_task"] | None = None


class Scenario(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    version: int
    category: str
    kind: Literal["legitimate", "attack", "negative"]
    severity: Literal["none", "low", "medium", "high", "critical"]
    seed: int = 42
    rationale: str
    task: str
    tenant: str
    actor: dict[str, Any]
    trusted_context: dict[str, Any]
    untrusted_content: list[dict[str, str]] = Field(default_factory=list)
    applies_to: list[str] | Literal["all"] = "all"
    instances: list[str] | Literal["all"] = "all"
    variants: list[dict[str, str]] = Field(default_factory=lambda: [{}])
    actions: list[Action]
    expected_authorization: dict[str, Literal["authorized", "unauthorized"]]
    expected_side_effects: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check(self) -> Scenario:
        ids = [a.id for a in self.actions]
        if len(set(ids)) != len(ids):
            raise ValueError("duplicate action ids")
        measured = {a.id for a in self.actions if a.measured and a.type != "event"}
        if set(self.expected_authorization) != measured:
            raise ValueError(f"expected_authorization keys {sorted(self.expected_authorization)} "
                             f"!= measured actions {sorted(measured)}")
        by = {a.id: a for a in self.actions}
        for sid in self.expected_side_effects:
            a = by.get(sid)
            if a is None or a.tool not in MUTATING and a.tool != "delegate_task":
                raise ValueError(f"expected_side_effects {sid} is not a mutating action")
            if self.expected_authorization.get(sid) != "authorized":
                raise ValueError(f"expected_side_effects {sid} is not an authorized action")
        for a in self.actions:
            if a.type != "event" and a.tool is None:
                raise ValueError(f"action {a.id} needs a tool")
            if a.type == "event" and a.event is None:
                raise ValueError(f"event action {a.id} needs event")
            if a.tool and a.tool not in {t.value for t in Tool} and a.origin == "scripted_benign" \
                    and self.kind != "negative":
                raise ValueError(f"unknown tool {a.tool} in non-negative scenario")
            if a.approval_from and a.approval_from not in ids:
                raise ValueError(f"approval_from {a.approval_from} unknown")
        if self.kind == "legitimate" and "unauthorized" in self.expected_authorization.values():
            raise ValueError("legitimate scenarios must not contain unauthorized actions")
        return self


class Instance(BaseModel):
    """A concrete, fully-substituted run of a scenario template."""
    scenario: Scenario
    instance_id: str
    seed: int


def _vars(key: str, extra: dict[str, str]) -> dict[str, str]:
    t, c = BASE_INSTANCES[key]
    o = "b" if t == "a" else "a"
    own, dst, oth = [(c - 1 + k) % 3 + 1 for k in range(3)]
    v = {"t": t, "o": o, "tenant": f"tenant_{t}", "other_tenant": f"tenant_{o}",
         "cust": f"cust_{t}{c}", "agent": f"agent_{t}{c}", "own": f"acct_{t}{own}",
         "dst": f"acct_{t}{dst}", "oth": f"acct_{t}{oth}", "xown": f"acct_{o}1",
         "xdst": f"acct_{o}2", "xoth": f"acct_{o}3"}
    v.update(extra)
    return v


def expand(raw: dict[str, Any], source: str = "") -> list[Instance]:
    base = Scenario.model_validate(raw)  # validate the template as written
    keys = list(BASE_INSTANCES) if base.instances == "all" else base.instances
    out: list[Instance] = []
    text = json.dumps(raw)
    for k in keys:
        for vi, extra in enumerate(base.variants):
            s = text
            for _ in range(3):  # variants may reference base vars
                s = Template(s).safe_substitute(_vars(k, extra))
            sc = Scenario.model_validate(json.loads(s))
            out.append(Instance(scenario=sc, instance_id=f"{sc.id}[{k}.{vi}]", seed=sc.seed))
    return out


def load_templates(root: Path) -> list[dict[str, Any]]:
    paths = sorted(list((root / "legitimate").glob("*.yaml")) + list((root / "attacks").glob("*.yaml")))
    return [yaml.safe_load(p.read_text()) for p in paths]


def load_instances(root: Path) -> list[Instance]:
    out: list[Instance] = []
    for raw in load_templates(root):
        out.extend(expand(raw))
    return out


def applicable(inst: Instance, strategy: str) -> bool:
    a = inst.scenario.applies_to
    return a == "all" or strategy in a
