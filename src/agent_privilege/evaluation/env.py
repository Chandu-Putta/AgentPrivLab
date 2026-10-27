"""Experiment environment: one DB + banking service + real MCP client shared across
scenario instances; a fresh Gateway per instance. Used by the evaluator and the tests."""
from __future__ import annotations

from pathlib import Path

from ..audit.journal import AuditJournal
from ..banking.db import Database
from ..banking.seed import seed
from ..banking.service import BankingService
from ..clock import Clock, FakeClock
from ..gateway.service import Gateway
from ..mcp_layer.client import McpBankingClient
from ..policy.registry import Strategy

ASSERTION_KEY = b"experiment-assertion-key-not-a-secret"
GRANT_KEY = b"experiment-grant-key-not-a-secret"
CONFIG_DIR = Path(__file__).resolve().parents[3] / "configs" / "strategies"


class Env:
    def __init__(self, seed_value: int = 42, journal: AuditJournal | None = None,
                 transport: str = "memory", clock: Clock | None = None) -> None:
        self.seed_value = seed_value
        self.clock = clock or FakeClock()
        self.db = Database()
        self.service = BankingService(self.db, ASSERTION_KEY, self.clock)
        self.journal = journal or AuditJournal()
        self.client = McpBankingClient()
        self.transport = transport

    async def __aenter__(self) -> Env:
        await self.client.connect_memory(self.service)
        return self

    async def __aexit__(self, *exc) -> None:
        await self.client.close()

    def reset(self) -> None:
        seed(self.db, self.seed_value)
        if isinstance(self.clock, FakeClock):
            self.clock._t = 1_700_000_000.0

    def gateway(self, strategy: Strategy, *, trace_id: str = "t", scenario_id: str = "s",
                run_id: str = "run", backend_defense: bool = False,
                reviewer_mode: str = "scripted") -> Gateway:
        return Gateway(strategy, self.db, self.client, self.clock, self.journal,
                       assertion_key=ASSERTION_KEY, grant_key=GRANT_KEY, run_id=run_id,
                       trace_id=trace_id, scenario_id=scenario_id, backend_defense=backend_defense,
                       reviewer_mode=reviewer_mode)
