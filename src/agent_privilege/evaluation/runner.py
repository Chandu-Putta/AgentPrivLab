"""Paired deterministic correctness runner: every applicable (scenario instance, strategy)
pair runs on identical seeded initial state with an injected clock."""
from __future__ import annotations

import asyncio
from dataclasses import asdict
from pathlib import Path
from typing import Any

from ..agents.trace_runner import ActionRow, run_instance
from ..audit.journal import AuditJournal
from ..policy.registry import ALL_STRATEGIES, build_strategy, load_strategy
from ..scenarios import Instance, applicable, load_instances
from .env import CONFIG_DIR, Env


async def _run(instances: list[Instance], strategies: list[str], *, seed: int, backend_defense: bool,
               reviewer_mode: str, run_id: str, journal: AuditJournal, config_dir: Path,
               overrides: dict[str, dict] | None = None) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    outcomes: list[dict[str, Any]] = []
    strat = {n: (build_strategy(overrides[n]) if overrides and n in overrides
                 else load_strategy(n, config_dir)) for n in strategies}
    async with Env(seed, journal) as env:
        for inst in instances:
            for name in strategies:
                if not applicable(inst, name):
                    continue
                res = await run_instance(env, strat[name], inst, run_id=run_id,
                                         backend_defense=backend_defense, reviewer_mode=reviewer_mode)
                for r in res.rows:
                    rows.append(asdict(r))
                outcomes.append({"instance_id": inst.instance_id, "scenario_id": inst.scenario.id,
                                 "category": inst.scenario.category, "kind": inst.scenario.kind,
                                 "strategy": name, "backend_defense": backend_defense,
                                 "reviewer_mode": reviewer_mode,
                                 "state_divergence": res.state_divergence,
                                 "n_actions": len(res.rows)})
    return rows, outcomes


def run_matrix(scenarios_dir: Path, strategies: list[str] | None = None, *, seed: int = 42,
               backend_defense: bool = False, reviewer_mode: str = "scripted", run_id: str = "run",
               journal: AuditJournal | None = None, config_dir: Path = CONFIG_DIR,
               instances: list[Instance] | None = None, overrides: dict[str, dict] | None = None):
    insts = instances if instances is not None else load_instances(scenarios_dir)
    return asyncio.run(_run(insts, strategies or ALL_STRATEGIES, seed=seed,
                            backend_defense=backend_defense, reviewer_mode=reviewer_mode,
                            run_id=run_id, journal=journal or AuditJournal(), config_dir=config_dir,
                            overrides=overrides))


__all__ = ["run_matrix", "ActionRow"]
