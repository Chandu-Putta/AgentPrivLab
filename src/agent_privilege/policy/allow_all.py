"""Control condition: agent talks to the tool server directly with a broad service key."""
from __future__ import annotations

from typing import Any

from ..models import PolicyResult
from .base import allow


class AllowAll:
    def __init__(self, config: dict[str, Any]) -> None:
        self.policy_id, self.version = config["id"], str(config["version"])

    def evaluate(self, i: dict[str, Any]) -> PolicyResult:
        return allow(self.policy_id, self.version, "no_enforcement")
