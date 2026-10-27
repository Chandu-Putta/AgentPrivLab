"""Load strategy configs (with `extends`) and build policy objects."""
from __future__ import annotations

import copy
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .allow_all import AllowAll
from .base import Policy, config_hash
from .external import ExternalPolicy
from .rbac import BroadRole, RestrictedRole
from .session import SessionScope
from .task import TaskCapability

KINDS = {"broad_role": BroadRole, "restricted_role": RestrictedRole, "session_scope": SessionScope,
         "task_capability": TaskCapability, "external": ExternalPolicy, "allow_all": AllowAll}

CORE_STRATEGIES = ["broad_role", "restricted_role", "session_scope", "task_capability",
                   "external_policy", "policy_plus_approval", "delegated_attenuation"]
CONTROL_STRATEGIES = ["delegated_naive", "external_policy_failopen", "direct_no_gateway"]
ALL_STRATEGIES = CORE_STRATEGIES + CONTROL_STRATEGIES


def _merge(base: dict, over: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in over.items():
        if k == "extends":
            continue
        out[k] = _merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


def load_config(name: str, directory: Path) -> dict[str, Any]:
    raw = yaml.safe_load((directory / f"{name}.yaml").read_text())
    if "extends" in raw:
        return _merge(load_config(raw["extends"], directory), raw)
    return raw


@dataclass
class Strategy:
    name: str
    config: dict[str, Any]
    policy: Policy
    policy_hash: str

    @property
    def kind(self) -> str:
        return self.config["kind"]

    @property
    def fail_mode(self) -> str:
        return self.config.get("fail_mode", "closed")

    @property
    def delegation_mode(self) -> str:
        return self.config.get("delegation", {}).get("mode", "forward")

    @property
    def max_depth(self) -> int:
        return int(self.config.get("delegation", {}).get("max_depth", 2))

    @property
    def approval(self) -> dict | None:
        return self.config.get("approval")

    @property
    def bypass_gateway(self) -> bool:
        return bool(self.config.get("bypass_gateway", False))


def build_strategy(config: dict[str, Any]) -> Strategy:
    pol = KINDS[config["kind"]](config)
    return Strategy(config["id"], config, pol, config_hash(config))


def load_strategy(name: str, directory: Path) -> Strategy:
    return build_strategy(load_config(name, directory))
