import asyncio

import pytest

from agent_privilege.evaluation.env import CONFIG_DIR, Env
from agent_privilege.policy.registry import load_strategy

ACTOR_A1 = {"agent_id": "agent_a1", "tenant": "tenant_a", "customer_id": "cust_a1"}


def intent(**kw):
    base = {"task_type": "pay_invoice", "tools": ["get_account", "list_transactions", "transfer_funds"],
            "accounts": ["acct_a1"], "destinations": ["acct_a2"], "max_amount": "200.00",
            "currency": "USD", "valid_for_s": 1800}
    base.update(kw)
    return base


@pytest.fixture
def strat():
    return lambda name: load_strategy(name, CONFIG_DIR)


def run_env(coro_fn, **env_kw):
    """Run `coro_fn(env)` inside a single event loop with a fresh seeded Env."""
    async def main():
        async with Env(**env_kw) as env:
            env.reset()
            return await coro_fn(env)
    return asyncio.run(main())
