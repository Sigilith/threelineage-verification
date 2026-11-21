#!/usr/bin/env python3
"""
ThreeLineage Safety-Availability Pareto Benchmark Harness (Stdlib Only).

Evaluates Binary (V1.0.0) vs. Adaptive Elastic governance across Regimes A, B, and C,
writing timestamped JSON results with a verified SHA-256 sidecar digest.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import random
import statistics

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

ACTIVE_CLUSTER_SIZE = 15
DIFFUSION_COEFF = 0.08
REVERSION_COEFF = 0.12
NOMINAL_NODE_LOAD = 0.45
SAFETY_CLIFF = 1.0


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

        for _ in range(n_runs):
            seq, onset = gen_fn(rng)
            history: list[StepInput] = []
            is_grid = len(seq[0].node_loads) > 0
            sim_nodes = list(seq[0].node_loads) if is_grid else []
            sim_load = max(sim_nodes) if is_grid else seq[0].coupled_load
            tripped = False
            first_intervention: int | None = None

            for item in seq:
                if tripped:
                    if onset == -1:
                        metrics.requested_benign_work += abs(item.proposed_delta)
                    continue

                if is_grid:
                    item.node_loads = list(sim_nodes)
                    item.coupled_load = max(sim_nodes)
                else:
                    item.coupled_load = sim_load

                dec = controller(history, item)
                history.append(item)

                if onset == -1:
                    metrics.requested_benign_work += abs(item.proposed_delta)
                    metrics.completed_benign_work += abs(dec.executed_delta)

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

                if sim_load >= SAFETY_CLIFF or (item.corrupt_state and dec.verdict != Verdict.FAIL_CLOSED):
                    metrics.safety_violations += 1
                    break

            if onset != -1 and first_intervention is not None and first_intervention >= onset:
                metrics.intervention_delays.append(first_intervention - onset)

        results[name] = metrics
    return results


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
        "harness_version": "1.1.0",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "runs_per_regime": args.runs,
        "seed": args.seed,
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
                avail = m.effective_availability
                avail_pct = round(avail * 100, 2) if avail is not None else None
                avail_str = f"{avail_pct:5.1f}%" if avail_pct is not None else "  N/A "

                delays = m.intervention_delays
                mean_d = round(statistics.mean(delays), 2) if delays else None
                med_d = round(statistics.median(delays), 2) if delays else None
                max_d = max(delays) if delays else None
                delay_str = f"{mean_d:.1f} steps" if mean_d is not None else "N/A"

                print(
                    f"{r_name:21s} | Viol: {m.safety_violations:4d} | "
                    f"FP Trips: {m.false_positive_trips:5d} | "
                    f"Eff.Avail: {avail_str} | "
                    f"Atten: {m.attenuated_steps:6d} | "
                    f"Escal: {m.escalations:6d} | Delay: {delay_str}"
                )
                profiles_out[prof_name][ctrl_name][r_name] = {
                    "safety_violations": m.safety_violations,
                    "false_positive_trips": m.false_positive_trips,
                    "effective_availability_pct": avail_pct,
                    "permit_full_steps": m.permit_full_steps,
                    "attenuated_steps": m.attenuated_steps,
                    "escalations": m.escalations,
                    "fail_closed_trips": m.fail_closed_trips,
                    "mean_intervention_delay_steps": mean_d,
                    "median_intervention_delay_steps": med_d,
                    "max_intervention_delay_steps": max_d,
                }

    report["profiles"] = profiles_out
    out_dir = Path("benchmarks/results")
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_file = out_dir / f"pareto_benchmark_{ts}.json"
    payload = json.dumps(report, indent=2) + "\n"
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    out_file.write_text(payload, encoding="utf-8")
    (out_dir / f"pareto_benchmark_{ts}.sha256").write_text(f"{digest}  {out_file.name}\n", encoding="utf-8")
    print(f"\nSaved artifact: {out_file}")
    print(f"SHA-256:        {digest}")


if __name__ == "__main__":
    main()
