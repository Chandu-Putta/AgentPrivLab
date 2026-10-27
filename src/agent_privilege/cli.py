"""agent-privilege command line interface."""
from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from .audit.replay import replay_file
from .banking.db import Database
from .banking.seed import seed as seed_db
from .policy.registry import ALL_STRATEGIES
from .scenarios import applicable, load_instances

logging.getLogger("mcp").setLevel(logging.WARNING)
logging.getLogger().setLevel(logging.WARNING)
ROOT = Path.cwd()


def _scen_dir(a) -> Path:
    return Path(getattr(a, "scenarios_dir", None) or "scenarios")


def cmd_seed(a) -> int:
    db = Database()
    seed_db(db, a.seed)
    snap = db.snapshot()
    print(f"seeded {len(snap['accounts'])} accounts, {len(snap['transactions'])} transactions (seed={a.seed})")
    for acct in snap["accounts"]:
        print(f"  {acct[0]} tenant={acct[1]} customer={acct[2]} balance_cents={acct[4]}")
    return 0


def cmd_validate(a) -> int:
    inst = load_instances(_scen_dir(a))
    ids = {i.scenario.id for i in inst}
    print(f"OK: {len(ids)} scenario templates, {len(inst)} instances")
    matrix = {}
    for i in inst:
        for s in ALL_STRATEGIES:
            matrix.setdefault(i.scenario.id, set())
            if applicable(i, s):
                matrix[i.scenario.id].add(s)
    for sid in sorted(matrix):
        n = len(matrix[sid])
        print(f"  {sid:42s} applies to {'all' if n == len(ALL_STRATEGIES) else sorted(matrix[sid])}")
    return 0


def cmd_test(a) -> int:
    from .evaluation.runner import run_matrix
    insts = [i for i in load_instances(_scen_dir(a)) if a.scenario in i.scenario.id]
    if not insts:
        print(f"no scenario matches '{a.scenario}'", file=sys.stderr)
        return 2
    rows, _ = run_matrix(_scen_dir(a), [a.strategy], instances=insts, backend_defense=a.backend_defense,
                         reviewer_mode=a.reviewer_mode)
    bad = 0
    for r in rows:
        ok = r["executed"] == (r["expected"] == "authorized")
        bad += not ok
        print(f'{"OK " if ok else "BAD"} {r["instance_id"]:38s} {r["step"]} {r["tool"]:18s} expected={r["expected"]:12s} '
              f'decision={r["decision"]:8s} outcome={r["outcome"]} reasons={r["reasons"]}')
    print(f"{len(rows) - bad}/{len(rows)} actions matched ground truth under {a.strategy}")
    return 0  # mismatches are findings, not tool failures


def cmd_evaluate(a) -> int:
    from .evaluation.pipeline import evaluate
    evaluate(Path(a.config), a.seed, Path(a.output), skip_performance=a.skip_performance)
    return 0


def cmd_replay(a) -> int:
    inp = Path(a.input)
    snaps = Path(a.policies) if a.policies else inp.parent / "policy_snapshots"
    rep = replay_file(inp, snaps)
    print(json.dumps(rep.summary(), indent=1))
    for n, why in rep.mismatches[:10]:
        print(f"  mismatch at record {n}: {why}")
    if rep.chain_breaks:
        print(f"  chain breaks at: {rep.chain_breaks[:10]}")
    if rep.incomplete:
        print(f"  incomplete records at: {rep.incomplete[:10]}")
    return 0 if rep.ok else 1


def cmd_report(a) -> int:
    from .evaluation.pipeline import report
    out = Path(a.input)
    if out.name == "deterministic":
        out = out.parent
    report(out)
    if a.format == "markdown":
        print((out / "summary.md").read_text())
    return 0


def cmd_serve_mcp(a) -> int:
    from .mcp_layer.server import main
    main()
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="agent-privilege", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("seed"); s.add_argument("--seed", type=int, default=42); s.set_defaults(fn=cmd_seed)
    s = sub.add_parser("scenarios"); ss = s.add_subparsers(dest="sub", required=True)
    v = ss.add_parser("validate"); v.set_defaults(fn=cmd_validate)
    s = sub.add_parser("test")
    s.add_argument("--strategy", required=True, choices=ALL_STRATEGIES)
    s.add_argument("--scenario", required=True, help="substring of scenario id, e.g. A01 or cross_tenant")
    s.add_argument("--backend-defense", action="store_true")
    s.add_argument("--reviewer-mode", default="scripted", choices=["scripted", "rubber_stamp", "always_reject"])
    s.set_defaults(fn=cmd_test)
    s = sub.add_parser("evaluate")
    s.add_argument("--config", default="configs/evaluation.yaml"); s.add_argument("--seed", type=int, default=42)
    s.add_argument("--output", required=True); s.add_argument("--skip-performance", action="store_true")
    s.set_defaults(fn=cmd_evaluate)
    s = sub.add_parser("replay-audit"); s.add_argument("--input", required=True)
    s.add_argument("--policies", help="directory of policy snapshots (default: <input dir>/policy_snapshots)")
    s.set_defaults(fn=cmd_replay)
    s = sub.add_parser("report"); s.add_argument("--input", required=True)
    s.add_argument("--format", default="markdown", choices=["markdown", "none"]); s.set_defaults(fn=cmd_report)
    s = sub.add_parser("serve-mcp"); s.set_defaults(fn=cmd_serve_mcp)
    a = p.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    raise SystemExit(main())
