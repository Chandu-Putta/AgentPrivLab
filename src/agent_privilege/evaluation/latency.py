"""Performance benchmark, SEPARATE from correctness runs. Machine-dependent; labeled as such.

Measures per strategy: gateway decision time (pre-check + policy only) and end-to-end
invocation latency (decision + assertion signing + MCP in-memory transport + backend),
CPU time, peak traced memory, policy evaluations and audit bytes. Warmups discarded.
p99 is reported only with >= 1000 samples."""
from __future__ import annotations

import asyncio
import os
import random
import time
import tracemalloc
from typing import Any

from ..audit.journal import AuditJournal
from ..mcp_layer.client import McpBankingClient
from ..policy.registry import ALL_STRATEGIES, load_strategy
from .env import ASSERTION_KEY, CONFIG_DIR, Env
from .statistics import MIN_SAMPLES_FOR_P99, bootstrap_ci, percentile

ACTOR = {"agent_id": "bench", "tenant": "tenant_a", "customer_id": "cust_a1"}
INTENT = {"task_type": "balance_check", "tools": ["get_account", "list_transactions", "transfer_funds"],
          "accounts": ["acct_a1"], "destinations": ["acct_a2"], "max_amount": "1.00", "max_total": "100000.00",
          "currency": "USD", "valid_for_s": 10**6}
MIX = [("get_account", {"account_id": "acct_a1"}, "allow"),
       ("list_transactions", {"account_id": "acct_a1"}, "allow"),
       ("get_account", {"account_id": "acct_b1"}, "deny")]


class _Counting:
    def __init__(self, inner) -> None:
        self.inner, self.n = inner, 0
        self.policy_id, self.version = inner.policy_id, inner.version

    def evaluate(self, i):
        self.n += 1
        return self.inner.evaluate(i)


async def _bench(strategy_name: str, calls: int, warmup: int, seed: int, *, measure_mem=False) -> dict[str, Any]:
    st = load_strategy(strategy_name, CONFIG_DIR)
    counter = _Counting(st.policy)
    st.policy = counter  # type: ignore[assignment]
    async with Env(seed, AuditJournal()) as env:
        env.reset()
        gw = env.gateway(st, trace_id="bench")
        tok = gw.start_task(ACTOR, {**INTENT, "task_type": "pay_invoice" if st.kind != "restricted_role" else "balance_check"},
                            "bench")
        # restricted/session templates are keyed by task_type; both have balance_check
        if st.kind in ("session_scope",):
            gw.ctxs["bench"].session["accounts"] = ["acct_a1"]
        total_calls = warmup + calls
        dec, e2e, kinds = [], [], []
        if measure_mem:
            tracemalloc.start()
        cpu0 = time.process_time()
        for i in range(total_calls):
            tool, params, kind = MIX[i % len(MIX)]
            r = await gw.invoke("bench", tool, params, grant_token=tok)
            if i >= warmup:
                dec.append(r.decision_us); e2e.append(r.total_us); kinds.append(kind)
        cpu = time.process_time() - cpu0
        peak = 0
        if measure_mem:
            peak = tracemalloc.get_traced_memory()[1]; tracemalloc.stop()
        return {"decision_us": dec, "e2e_us": e2e, "kinds": kinds, "cpu_s": cpu, "peak_bytes": peak,
                "policy_evals": counter.n, "audit_bytes": env.journal.audit_bytes(), "calls": total_calls}


async def _approval_path(n: int, seed: int) -> dict[str, list[int]]:
    st = load_strategy("policy_plus_approval", CONFIG_DIR)
    async with Env(seed, AuditJournal()) as env:
        env.reset()
        gw = env.gateway(st, trace_id="ap")
        gw.start_task(ACTOR, {**INTENT, "task_type": "pay_invoice", "max_amount": "600.00"}, "ap")
        dec, e2e = [], []
        for i in range(n):
            r = await gw.invoke("bench", "transfer_funds",
                                {"source_id": "acct_a1", "destination_id": "acct_a2", "amount": "501.00",
                                 "currency": "USD", "idempotency_key": f"ap{i}"}, scripted_reviewer="approve")
            dec.append(r.decision_us); e2e.append(r.total_us)
    return {"decision_us": dec, "e2e_us": e2e}


async def _stdio(n: int, seed: int) -> list[int]:
    """Real stdio subprocess MCP server (separate process, own seeded DB)."""
    st = load_strategy("external_policy", CONFIG_DIR)
    from ..clock import SystemClock
    env = Env(seed, AuditJournal(), clock=SystemClock())
    env.reset()
    c = McpBankingClient()
    await c.connect_stdio({**os.environ, "AGENTPRIV_ASSERTION_KEY": ASSERTION_KEY.decode(),
                           "AGENTPRIV_SEED": str(seed)})
    env.client = c
    try:
        gw = env.gateway(st, trace_id="stdio")
        gw.start_task(ACTOR, INTENT, "stdio")
        out = []
        for i in range(n + 20):
            r = await gw.invoke("bench", "get_account", {"account_id": "acct_a1"})
            assert r.executed, r.outcome
            if i >= 20:
                out.append(r.total_us)
        return out
    finally:
        await c.close()


def _summ(vals: list[int], seed: int, n_boot: int) -> dict[str, Any]:
    out: dict[str, Any] = {"n": len(vals)}
    for q in (50, 95, 99):
        if q == 99 and len(vals) < MIN_SAMPLES_FOR_P99:
            out.update({"p99": None, "p99_lo": None, "p99_hi": None})
            continue
        lo, hi = bootstrap_ci(vals, lambda a, q=q: float(__import__("numpy").percentile(a, q)),
                              seed=seed, n_boot=n_boot)
        out.update({f"p{q}": percentile(vals, q), f"p{q}_lo": lo, f"p{q}_hi": hi})
    return out


def run_latency(*, calls: int, warmup: int, repeats: int, stdio_calls: int, approval_calls: int,
                n_boot: int, seed: int) -> tuple[list[dict], list[dict], list[dict]]:
    """Return (summary rows, raw latency rows, resource rows)."""
    rng = random.Random(seed)
    order = [(s, r) for s in ALL_STRATEGIES for r in range(repeats)]
    rng.shuffle(order)  # interleave strategies to spread machine drift
    pooled: dict[tuple[str, str], dict[str, list[int]]] = {}
    res_rows: dict[str, dict[str, float]] = {}
    raw: list[dict] = []
    for s, rep in order:
        r = asyncio.run(_bench(s, calls, warmup, seed))
        for k, d, e in zip(r["kinds"], r["decision_us"], r["e2e_us"], strict=True):
            p = pooled.setdefault((s, k), {"decision_us": [], "e2e_us": []})
            p["decision_us"].append(d); p["e2e_us"].append(e)
            raw.append({"strategy": s, "repeat": rep, "path": k, "decision_us": d, "e2e_us": e})
        acc = res_rows.setdefault(s, {"cpu_s": 0.0, "calls": 0, "policy_evals": 0, "audit_bytes": 0})
        acc["cpu_s"] += r["cpu_s"]; acc["calls"] += r["calls"]
        acc["policy_evals"] += r["policy_evals"]; acc["audit_bytes"] += r["audit_bytes"]
    for s in ALL_STRATEGIES:
        m = asyncio.run(_bench(s, min(calls, 500), 50, seed, measure_mem=True))
        res_rows[s]["peak_traced_bytes"] = m["peak_bytes"]
    ap = asyncio.run(_approval_path(approval_calls, seed))
    for _i, (d, e) in enumerate(zip(ap["decision_us"], ap["e2e_us"], strict=True)):
        raw.append({"strategy": "policy_plus_approval", "repeat": 0, "path": "approval_escalated",
                    "decision_us": d, "e2e_us": e})
        pooled.setdefault(("policy_plus_approval", "approval_escalated"), {"decision_us": [], "e2e_us": []})
        pooled[("policy_plus_approval", "approval_escalated")]["decision_us"].append(d)
        pooled[("policy_plus_approval", "approval_escalated")]["e2e_us"].append(e)
    st = asyncio.run(_stdio(stdio_calls, seed))
    for _i, e in enumerate(st):
        raw.append({"strategy": "external_policy", "repeat": 0, "path": "allow_stdio_subprocess",
                    "decision_us": -1, "e2e_us": e})
    summary = []
    for (s, k), v in sorted(pooled.items()):
        for metric in ("decision_us", "e2e_us"):
            summary.append({"strategy": s, "path": k, "metric": metric, **_summ(v[metric], seed, n_boot)})
    summary.append({"strategy": "external_policy", "path": "allow_stdio_subprocess", "metric": "e2e_us",
                    **_summ(st, seed, n_boot)})
    resources = [{"strategy": s, "cpu_us_per_call": v["cpu_s"] / v["calls"] * 1e6,
                  "policy_evals_per_call": v["policy_evals"] / v["calls"],
                  "audit_bytes_per_call": v["audit_bytes"] / v["calls"],
                  "peak_traced_bytes": v["peak_traced_bytes"]} for s, v in res_rows.items()]
    return summary, raw, resources
