#!/usr/bin/env python3
"""
ThreeLineage Safety-Availability Pareto Benchmark Harness (Stdlib Only).

Evaluates Binary (V1.0.0) vs. Adaptive Elastic governance across Regimes A, B, and C,
emitting self-verifying JSON artifacts, SHA-256 digests, and Markdown audit reports.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import statistics
import subprocess
import time

from benchmarks.controllers.binary_v1 import binary_v1_controller
from benchmarks.controllers.elastic_v2 import elastic_v2_controller
from benchmarks.regimes.coupled_grid import (
    gen_grid_regime_a_benign,
    gen_grid_regime_b_slow_drift,
    gen_grid_regime_c_adversarial,
)
from benchmarks.regimes.single_node import (
    gen_regime_a_benign,
    gen_regime_b_slow_drift,
    gen_regime_c_adversarial,
)
from benchmarks.types import Decision, RunMetrics, StepInput, Verdict

RegimeGen = Callable[[random.Random], tuple[list[StepInput], int]]
ControllerFn = Callable[[list[StepInput], StepInput], Decision]

HARNESS_VERSION = "1.2.0"
ACTIVE_CLUSTER_SIZE = 15
DIFFUSION_COEFF = 0.08
REVERSION_COEFF = 0.12
NOMINAL_NODE_LOAD = 0.45
SAFETY_CLIFF = 1.0


def _git_cmd(args: list[str]) -> str:
    try:
        return subprocess.check_output(["git", *args], stderr=subprocess.DEVNULL, text=True).strip()
    except Exception:
        return "unavailable"


def _get_mem_total() -> str:
    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            if line.startswith("MemTotal:"):
                kb = int(line.split()[1])
                return f"{kb / (1024 * 1024):.2f} GiB"
    except Exception:
        pass
    return "unavailable"


def collect_integrity_metadata(seed: int, runs: int) -> dict[str, object]:
    """Capture repository and host environment metadata for the benchmark artifact."""
    dirty = _git_cmd(["status", "--porcelain"])
    return {
        "harness_version": HARNESS_VERSION,
        "repository": Path.cwd().name,
        "branch": _git_cmd(["branch", "--show-current"]),
        "commit_hash": _git_cmd(["rev-parse", "HEAD"]),
        "working_tree_clean": (dirty == ""),
        "runs_per_regime": runs,
        "random_seed": seed,
        "environment": {
            "os": f"{platform.system()} {platform.release()}",
            "architecture": platform.machine(),
            "kernel": _git_cmd(["uname", "-r"]) if Path("/usr/bin/uname").exists() else platform.release(),
            "cpu_cores": os.cpu_count(),
            "ram_capacity": _get_mem_total(),
            "python_version": platform.python_version(),
        },
    }


def step_coupled_nodes(nodes: list[float], executed_delta: float, benign: bool) -> list[float]:
    """Advance coupled ring topology by one simulation step."""
    n = len(nodes)
    updated = list(nodes)
    for i in range(n):
        left = nodes[(i - 1) % n]
        right = nodes[(i + 1) % n]
        diffusion = DIFFUSION_COEFF * (left + right - 2.0 * nodes[i])
        injection = executed_delta if i < ACTIVE_CLUSTER_SIZE else 0.0
        reversion = -REVERSION_COEFF * (nodes[i] - NOMINAL_NODE_LOAD) if benign else 0.0
        updated[i] = max(0.05, updated[i] + injection + diffusion + reversion)
    return updated


def evaluate_suite(
    controller: ControllerFn,
    regimes: dict[str, RegimeGen],
    n_runs: int = 1000,
    seed: int = 2026,
) -> dict[str, RunMetrics]:
    """Run deterministic Monte Carlo trials across each regime for a controller."""
    results: dict[str, RunMetrics] = {}

    for name, gen_fn in regimes.items():
        rng = random.Random(seed)
        metrics = RunMetrics()
        t_start = time.perf_counter()

        for _ in range(n_runs):
            seq, onset = gen_fn(rng)
            history: list[StepInput] = []
            is_grid = len(seq[0].node_loads) > 0
            sim_nodes = list(seq[0].node_loads) if is_grid else []
            sim_load = max(sim_nodes) if is_grid else seq[0].coupled_load
            tripped = False
            first_intervention: int | None = None
            trial_req = 0.0
            trial_done = 0.0

            for item in seq:
                if tripped:
                    if onset == -1:
                        trial_req += abs(item.proposed_delta)
                    continue

                if is_grid:
                    item.node_loads = list(sim_nodes)
                    item.coupled_load = max(sim_nodes)
                else:
                    item.coupled_load = sim_load

                dec = controller(history, item)
                history.append(item)
                metrics.total_evaluated_steps += 1

                if onset == -1:
                    trial_req += abs(item.proposed_delta)
                    trial_done += abs(dec.executed_delta)

                if dec.verdict != Verdict.PERMIT_FULL and first_intervention is None:
                    first_intervention = item.step

                if dec.verdict == Verdict.PERMIT_FULL:
                    metrics.permit_full_steps += 1
                elif dec.verdict == Verdict.PERMIT_ATTENUATED:
                    metrics.attenuated_steps += 1
                elif dec.verdict == Verdict.HOLD_ESCALATE:
                    metrics.escalations += 1
                elif dec.verdict == Verdict.FAIL_CLOSED:
                    tripped = True
                    metrics.fail_closed_trips += 1
                    if onset == -1:
                        metrics.false_positive_trips += 1

                if is_grid:
                    sim_nodes = step_coupled_nodes(sim_nodes, dec.executed_delta, benign=(onset == -1))
                    sim_load = max(sim_nodes)
                else:
                    sim_load += dec.executed_delta
                    if onset == -1:
                        sim_load -= REVERSION_COEFF * (sim_load - NOMINAL_NODE_LOAD)

                hard_breach = sim_load >= SAFETY_CLIFF
                escape_breach = (
                    (item.corrupt_state and dec.verdict != Verdict.FAIL_CLOSED)
                    or (dec.verdict in (Verdict.HOLD_ESCALATE, Verdict.FAIL_CLOSED) and dec.executed_delta != 0.0)
                )
                if hard_breach or escape_breach:
                    if hard_breach:
                        metrics.hard_invariant_violations += 1
                    if escape_breach:
                        metrics.constraint_escapes += 1
                    break

            if onset == -1 and trial_req > 0.0:
                metrics.requested_benign_work += trial_req
                metrics.completed_benign_work += trial_done
                metrics.trial_completion_rates.append(trial_done / trial_req)

            if onset != -1 and first_intervention is not None and first_intervention >= onset:
                metrics.intervention_delays.append(first_intervention - onset)

        metrics.elapsed_seconds = time.perf_counter() - t_start
        results[name] = metrics
    return results


def _format_regime_metrics(m: RunMetrics) -> dict[str, object]:
    total = max(1, m.total_evaluated_steps)
    avail = m.effective_availability
    mean_comp = m.mean_task_completion_rate
    delays = m.intervention_delays

    return {
        "safety_metrics": {
            "hard_invariant_violations": m.hard_invariant_violations,
            "constraint_escapes": m.constraint_escapes,
            "fail_closed_activations": m.fail_closed_trips,
            "false_positive_trips": m.false_positive_trips,
        },
        "availability_metrics": {
            "effective_availability_pct": round(avail * 100, 2) if avail is not None else None,
            "permit_throughput_pct": round(m.permit_throughput_pct, 2),
            "permits_per_sec": round(m.permits_per_sec, 1),
            "mean_task_completion_rate_pct": round(mean_comp * 100, 2) if mean_comp is not None else None,
        },
        "governance_metrics": {
            "total_evaluated_steps": m.total_evaluated_steps,
            "permit_full_count": m.permit_full_steps,
            "permit_full_freq_pct": round((m.permit_full_steps / total) * 100, 2),
            "permit_attenuated_count": m.attenuated_steps,
            "permit_attenuated_freq_pct": round((m.attenuated_steps / total) * 100, 2),
            "hold_escalate_count": m.escalations,
            "hold_escalate_freq_pct": round((m.escalations / total) * 100, 2),
            "fail_closed_count": m.fail_closed_trips,
            "fail_closed_freq_pct": round((m.fail_closed_trips / total) * 100, 2),
        },
        "detection_metrics": {
            "mean_intervention_delay_steps": round(statistics.mean(delays), 2) if delays else None,
            "median_intervention_delay_steps": round(statistics.median(delays), 2) if delays else None,
            "worst_case_intervention_delay_steps": max(delays) if delays else None,
        },
    }


def render_markdown_report(report: dict[str, object], json_path: Path, digest: str) -> str:
    """Render a full Markdown audit report covering all four metric categories and integrity metadata."""
    integrity = report["benchmark_integrity"]
    env = integrity["environment"]
    lines = [
        f"# ThreeLineage Safety–Availability Pareto Benchmark Report (`{json_path.stem}`)",
        "",
        "## Benchmark Integrity",
        f"- **Harness Version:** `v{integrity['harness_version']}`",
        f"- **Timestamp (UTC):** `{report['timestamp_utc']}`",
        f"- **Repository / Branch:** `{integrity['repository']}` (`{integrity['branch']}`)",
        f"- **Commit Hash:** `{integrity['commit_hash']}`",
        f"- **Random Seed:** `{integrity['random_seed']}` (`N = {integrity['runs_per_regime']:,}` trials/regime)",
        f"- **Artifact SHA-256:** `{digest}`",
        f"- **Environment:** `{env['os']} ({env['architecture']})` | Kernel `{env['kernel']}` | `{env['cpu_cores']}` cores | `{env['ram_capacity']}` RAM | Python `{env['python_version']}`",
        "",
    ]

    for prof_name, controllers in report["profiles"].items():
        lines.extend([f"## Profile: `{prof_name}`", ""])
        for ctrl_name, regimes in controllers.items():
            lines.extend([
                f"### Controller: `{ctrl_name}`",
                "",
                "| Regime | Hard Viol / Escapes | Fail-Closed Act. | Eff. Avail | Permit Thruput | Mean Task Comp. | PERMIT_FULL | PERMIT_ATTEN | HOLD_ESCALATE | FAIL_CLOSED | Delay (Mean / Med / Worst) |",
                "| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |",
            ])
            for r_name, data in regimes.items():
                s = data["safety_metrics"]
                a = data["availability_metrics"]
                g = data["governance_metrics"]
                d = data["detection_metrics"]

                eff = f"{a['effective_availability_pct']:.1f}%" if a["effective_availability_pct"] is not None else "N/A"
                comp = (
                    f"{a['mean_task_completion_rate_pct']:.1f}%"
                    if a["mean_task_completion_rate_pct"] is not None
                    else "N/A"
                )
                thru = f"{a['permit_throughput_pct']:.1f}% ({a['permits_per_sec']:,.0f}/s)"
                if d["mean_intervention_delay_steps"] is not None:
                    delay_str = (
                        f"{d['mean_intervention_delay_steps']:.1f} / "
                        f"{d['median_intervention_delay_steps']:.1f} / "
                        f"{d['worst_case_intervention_delay_steps']}"
                    )
                else:
                    delay_str = "N/A"

                lines.append(
                    f"| `{r_name}` | {s['hard_invariant_violations']} / {s['constraint_escapes']} | "
                    f"{s['fail_closed_activations']} | {eff} | {thru} | {comp} | "
                    f"{g['permit_full_freq_pct']:.1f}% | {g['permit_attenuated_freq_pct']:.1f}% | "
                    f"{g['hold_escalate_freq_pct']:.1f}% | {g['fail_closed_freq_pct']:.1f}% | {delay_str} |"
                )
            lines.append("")

    lines.extend([
        "## Publication Verification Statement",
        (
            "All benchmark results were generated from version-controlled source code using a documented "
            "execution environment, fixed scenario definitions, recorded random seeds, and cryptographically "
            "hashed output artifacts. Results demonstrate behaviour within the tested benchmark environment "
            "only and should not be interpreted as certification, regulatory approval, or evidence of "
            "production deployment suitability."
        ),
        "",
    ])
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="ThreeLineage Safety-Availability Pareto Benchmark")
    parser.add_argument("--runs", type=int, default=1000, help="Trials per regime (default: 1000)")
    parser.add_argument("--seed", type=int, default=2026, help="Deterministic PRNG seed")
    parser.add_argument("--profile", choices=["single", "grid", "both"], default="both")
    args = parser.parse_args()

    profiles: dict[str, dict[str, RegimeGen]] = {}
    if args.profile in ("single", "both"):
        profiles["Single_Node"] = {
            "A_Benign_Volatility": gen_regime_a_benign,
            "B_Slow_Drift": gen_regime_b_slow_drift,
            "C_Adversarial_Drift": gen_regime_c_adversarial,
        }
    if args.profile in ("grid", "both"):
        profiles["Coupled_100_Node_Grid"] = {
            "A_Benign_Volatility": gen_grid_regime_a_benign,
            "B_Slow_Drift": gen_grid_regime_b_slow_drift,
            "C_Adversarial_Drift": gen_grid_regime_c_adversarial,
        }

    controllers: dict[str, ControllerFn] = {
        "Binary_V1": binary_v1_controller,
        "Elastic_V2": elastic_v2_controller,
    }

    report: dict[str, object] = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "benchmark_integrity": collect_integrity_metadata(seed=args.seed, runs=args.runs),
        "profiles": {},
    }

    profiles_out: dict[str, dict[str, dict[str, object]]] = {}
    for prof_name, regimes in profiles.items():
        print(f"\n==================== {prof_name} (N={args.runs}) ====================")
        profiles_out[prof_name] = {}
        for ctrl_name, ctrl_fn in controllers.items():
            print(f"\n--- {ctrl_name} ---")
            res = evaluate_suite(ctrl_fn, regimes, n_runs=args.runs, seed=args.seed)
            profiles_out[prof_name][ctrl_name] = {}
            for r_name, m in res.items():
                formatted = _format_regime_metrics(m)
                profiles_out[prof_name][ctrl_name][r_name] = formatted
                a = formatted["availability_metrics"]
                d = formatted["detection_metrics"]
                avail_str = f"{a['effective_availability_pct']:5.1f}%" if a["effective_availability_pct"] is not None else "  N/A "
                delay_str = (
                    f"{d['mean_intervention_delay_steps']:.1f}/{d['median_intervention_delay_steps']:.1f}/{d['worst_case_intervention_delay_steps']}"
                    if d["mean_intervention_delay_steps"] is not None
                    else "N/A"
                )
                print(
                    f"{r_name:21s} | Viol: {m.safety_violations:2d} | "
                    f"FC: {m.fail_closed_trips:5d} | "
                    f"Eff.Avail: {avail_str} | "
                    f"Thru: {m.permit_throughput_pct:5.1f}% | "
                    f"Delay(M/Med/Max): {delay_str}"
                )

    report["profiles"] = profiles_out
    out_dir = Path("benchmarks/results")
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_file = out_dir / f"pareto_benchmark_{ts}.json"
    payload = json.dumps(report, indent=2) + "\n"
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    out_file.write_text(payload, encoding="utf-8")
    (out_dir / f"pareto_benchmark_{ts}.sha256").write_text(f"{digest}  {out_file.name}\n", encoding="utf-8")

    md_file = out_dir / f"pareto_report_{ts}.md"
    md_file.write_text(render_markdown_report(report, out_file, digest), encoding="utf-8")

    print(f"\nSaved JSON:   {out_file}")
    print(f"Saved Report: {md_file}")
    print(f"SHA-256:      {digest}")


if __name__ == "__main__":
    main()
