"""Figures generated from measured CSVs only (no hardcoded numbers)."""
from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

from ..policy.registry import CONTROL_STRATEGIES, CORE_STRATEGIES  # noqa: E402

BLUE, ORANGE, GREEN, GRAY, RED = "#0072B2", "#E69F00", "#009E73", "#8A8A8A", "#D55E00"
LABEL = {"broad_role": "broad role", "restricted_role": "restricted role", "session_scope": "session scope",
         "task_capability": "task capability", "external_policy": "external policy",
         "policy_plus_approval": "policy + approval", "delegated_attenuation": "delegated attenuation",
         "delegated_naive": "(ctl) naive delegation", "external_policy_failopen": "(ctl) fail-open policy",
         "direct_no_gateway": "(ctl) direct, no gateway"}


def _save(fig, d: Path, name: str) -> None:
    d.mkdir(parents=True, exist_ok=True)
    fig.savefig(d / f"{name}.png", dpi=150, bbox_inches="tight")
    fig.savefig(d / f"{name}.svg", bbox_inches="tight")
    plt.close(fig)


def _get(metrics, strategy, metric, condition="primary", scope="common"):
    for m in metrics:
        if (m["strategy"], m["metric"], m["condition"], m["scope"]) == (strategy, metric, condition, scope):
            return m
    return None


def uer_by_strategy(metrics, out: Path) -> None:
    order = CORE_STRATEGIES + CONTROL_STRATEGIES
    rows = [(s, _get(metrics, s, "unauthorized_execution_rate")) for s in order]
    rows = [(s, m) for s, m in rows if m]
    fig, ax = plt.subplots(figsize=(8, 4.6))
    for i, (s, m) in enumerate(rows):
        col = BLUE if s in CORE_STRATEGIES else GRAY
        ax.barh(i, m["rate"], color=col, height=0.6)
        ax.errorbar(m["rate"], i, xerr=[[m["rate"] - m["ci_lo"]], [m["ci_hi"] - m["rate"]]], color="black", capsize=3, lw=1)
        ax.text(min(m["ci_hi"], 0.93) + 0.01, i, f'{m["k"]}/{m["n"]}', va="center", fontsize=8)
    ax.set_yticks(range(len(rows)), [LABEL[s] for s, _ in rows]); ax.invert_yaxis()
    ax.set_xlim(0, 1.05); ax.set_xlabel("Unauthorized execution rate (95% Wilson CI), scripted adversarial traces")
    ax.set_title("Unauthorized actions executed / attempted (common scenarios)", fontsize=10)
    ax.spines[["top", "right"]].set_visible(False)
    _save(fig, out, "unauthorized_execution_rate")


def tradeoff(metrics, out: Path) -> None:
    fig, ax = plt.subplots(figsize=(6.4, 4.8))
    for s in CORE_STRATEGIES + CONTROL_STRATEGIES:
        u = _get(metrics, s, "unauthorized_execution_rate"); f = _get(metrics, s, "per_call_success_rate")
        if not (u and f):
            continue
        x = 1 - f["rate"]
        ax.scatter(x, u["rate"], color=BLUE if s in CORE_STRATEGIES else GRAY, s=45, zorder=3)
        ax.annotate(LABEL[s], (x, u["rate"]), textcoords="offset points", xytext=(5, 4), fontsize=7)
    ax.set_xlabel("Authorized actions NOT executed (denied/rejected/failed)"); ax.set_ylabel("Unauthorized execution rate")
    ax.set_title("Security vs. legitimate-work trade-off (common scenarios)", fontsize=10)
    ax.spines[["top", "right"]].set_visible(False)
    _save(fig, out, "security_vs_usability")


def category_heatmap(metrics, out: Path) -> None:
    import numpy as np
    cats = sorted({m["metric"][len("uer_by_category["):-1] for m in metrics
                   if m["metric"].startswith("uer_by_category[") and m["condition"] == "primary" and m["scope"] == "common"})
    strat = CORE_STRATEGIES
    grid = np.full((len(cats), len(strat)), np.nan)
    for j, s in enumerate(strat):
        for i, c in enumerate(cats):
            m = _get(metrics, s, f"uer_by_category[{c}]")
            if m:
                grid[i, j] = m["rate"]
    fig, ax = plt.subplots(figsize=(8, 0.38 * len(cats) + 1.6))
    im = ax.imshow(grid, cmap="Blues", vmin=0, vmax=1, aspect="auto")
    ax.set_xticks(range(len(strat)), [LABEL[s] for s in strat], rotation=30, ha="right", fontsize=8)
    ax.set_yticks(range(len(cats)), cats, fontsize=8)
    for i in range(len(cats)):
        for j in range(len(strat)):
            if not np.isnan(grid[i, j]):
                ax.text(j, i, f"{grid[i, j]:.2f}", ha="center", va="center", fontsize=7,
                        color="white" if grid[i, j] > 0.55 else "black")
    fig.colorbar(im, ax=ax, label="unauthorized execution rate")
    ax.set_title("Unauthorized execution rate by attack category", fontsize=10)
    _save(fig, out, "uer_by_category")


def latency_plot(summary, out: Path) -> None:
    rows = [r for r in summary if r["path"] == "allow" and r["metric"] in ("decision_us", "e2e_us")]
    order = [s for s in CORE_STRATEGIES + CONTROL_STRATEGIES if any(r["strategy"] == s for r in rows)]
    fig, axes = plt.subplots(1, 2, figsize=(10, 4.2), sharey=True)
    for ax, metric, title in zip(axes, ("decision_us", "e2e_us"),
                                 ("Gateway decision time (µs)", "End-to-end invocation latency (µs)"), strict=True):
        for i, s in enumerate(order):
            r = next((x for x in rows if x["strategy"] == s and x["metric"] == metric), None)
            if not r:
                continue
            for q, col, off in (("p50", BLUE, -0.12), ("p95", ORANGE, 0.12)):
                ax.errorbar(float(r[q]), i + off, xerr=[[float(r[q]) - float(r[q + "_lo"])], [float(r[q + "_hi"]) - float(r[q])]],
                            fmt="o", color=col, capsize=2, ms=4, label=q if i == 0 else None)
        ax.set_yticks(range(len(order)), [LABEL[s] for s in order], fontsize=8); ax.invert_yaxis()
        ax.set_title(title, fontsize=9); ax.spines[["top", "right"]].set_visible(False)
    axes[1].legend(frameon=False, fontsize=8, loc="lower right")
    axes[0].set_xlabel("timer resolution is 1 µs", fontsize=7)
    fig.suptitle("Local, in-process MCP transport; machine-dependent (bootstrap 95% CI)", fontsize=9)
    _save(fig, out, "latency")


def approval_plot(sweep, out: Path) -> None:
    fig, ax = plt.subplots(figsize=(6.4, 4.4))
    sel = [r for r in sweep if float(r["malicious_fraction"]) == 0.05]
    combos = sorted({(float(r["base_error"]), float(r["fatigue_slope"])) for r in sel})
    cols = [BLUE, ORANGE, GREEN, RED, GRAY, "#CC79A7", "#56B4E9", "#F0E442", "#000000"]
    for c, (b, sl) in zip(cols, combos, strict=False):
        pts = sorted((int(r["shift_length"]), float(r["false_approval_rate"])) for r in sel
                     if (float(r["base_error"]), float(r["fatigue_slope"])) == (b, sl))
        ax.plot(*zip(*pts, strict=True), marker="o", color=c, label=f"base {b:.2f}, slope {sl:g}", lw=1.2)
    ax.set_xscale("log"); ax.set_xlabel("approvals handled per shift"); ax.set_ylabel("malicious requests approved")
    ax.set_title("SIMULATED reviewer fatigue (assumed model, not human data)", fontsize=9)
    ax.legend(fontsize=6, frameon=False, ncol=1); ax.spines[["top", "right"]].set_visible(False)
    _save(fig, out, "approval_fatigue_simulation")


def reviewer_plot(metrics, out: Path) -> None:
    items = [("external_policy", "primary", "external policy\n(no approval)"),
             ("policy_plus_approval", "primary", "policy+approval\nscripted reviewer"),
             ("policy_plus_approval", "rubber_stamp", "policy+approval\nrubber-stamp"),
             ("policy_plus_approval", "always_reject", "policy+approval\nalways reject")]
    fig, ax = plt.subplots(figsize=(6.4, 4))
    for i, (s, c, _lab) in enumerate(items):
        m = _get(metrics, s, "unauthorized_execution_rate", c)
        if m:
            ax.bar(i, m["rate"], color=BLUE if i < 2 else GRAY)
            ax.text(i, m["rate"] + 0.004, f'{m["k"]}/{m["n"]}', ha="center", fontsize=8)
    ax.set_xticks(range(len(items)), [x[2] for x in items], fontsize=8)
    ax.set_ylabel("Unauthorized execution rate"); ax.spines[["top", "right"]].set_visible(False)
    ax.set_title("Approval value depends on the (simulated) reviewer", fontsize=10)
    _save(fig, out, "reviewer_sensitivity")
