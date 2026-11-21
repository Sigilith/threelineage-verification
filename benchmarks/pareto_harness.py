#!/usr/bin/env python3
"""
ThreeLineage Safety-Availability Pareto Benchmark Harness (Stdlib Only).
Evaluates Binary (V1.0.0) vs. Adaptive Elastic governance across Regimes A, B, and C,
writing timestamped JSON results with a SHA-256 verification digest.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import random
import statistics
from typing import Callable, Dict, List, Tuple

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

RegimeGen = Callable[[random.Random], Tuple[List[StepInput], int]]
ControllerFn = Callable[[List[StepInput], StepInput], Decision]


def _step_coupled_nodes(nodes: List[float], executed_delta: float, benign: bool) -> List[float]:
    n = len(nodes)
    updated = list(nodes)
    # Apply actuation to active 15-node feeder cluster and diffuse across neighbors
    for i in range(n):
        left = nodes[(i - 1) % n]
        right = nodes[(i + 1) % n]
        diffusion = 0.08 * (left + right - 2.0 * nodes[i])
        injection = executed_delta if i < 15 else 0.0
        reversion = -0.12 * (nodes[i] - 0.45) if benign else 0.0
        updated[i] = max(0.05, updated[i] + injection + diffusion + reversion)
    return updated


def evaluate_suite(
    controller: ControllerFn,
    regimes: Dict[str, RegimeGen],
    n_runs: int = 1000,
    seed: int = 2026,
) -> Dict[str, RunMetrics]:
    results: Dict[str, RunMetrics] = {}

    for name, gen_fn in regimes.items():
        rng = random.Random(seed)
        metrics = RunMetrics()

        for _ in range(n_runs):
            seq, onset = gen_fn(rng)
            history: List[StepInput] = []
            is_grid = len(seq[0].node_loads) > 0
            sim_nodes = list(seq[0].node_loads) if is_grid else []
            sim_load = max(sim_nodes) if is_grid else seq[0].coupled_load
            tripped = False
            first_intervention = None

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

                if dec.verdict == Verdict.PERMIT_ATTENUATED:
                    metrics.attenuated_steps += 1
                elif dec.verdict == Verdict.HOLD_ESCALATE:
                    metrics.escalations += 1
                elif dec.verdict == Verdict.FAIL_CLOSED:
                    tripped = True
                    if onset == -1:
                        metrics.false_positive_trips += 1

                if is_grid:
                    sim_nodes = _step_coupled_nodes(sim_nodes, dec.executed_delta, benign=(onset == -1))
                    sim_load = max(sim_nodes)
                else:
                    sim_load += dec.executed_delta
                    if onset == -1:
                        sim_load -= 0.12 * (sim_load - 0.45)

                if sim_load >= 1.0 or (item.corrupt_state and dec.verdict != Verdict.FAIL_CLOSED):
                    metrics.safety_violations += 1
                    break

            if onset != -1 and first_intervention is not None and first_intervention >= onset:
                metrics.intervention_delays.append(first_intervention - onset)

        results[name] = metrics
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="ThreeLineage Safety-Availability Pareto Benchmark")
    parser.add_argument("--runs", type=int, default=1000, help="Runs per regime (default: 1000)")
    parser.add_argument("--seed", type=int, default=2026, help="Deterministic PRNG seed")
    parser.add_argument("--profile", choices=["single", "grid", "both"], default="both")
    args = parser.parse_args()

    profiles: Dict[str, Dict[str, RegimeGen]] = {}
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

    controllers: Dict[str, ControllerFn] = {
        "Binary_V1": binary_v1_controller,
        "Elastic_V2": elastic_v2_controller,
    }

    report = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "runs_per_regime": args.runs,
        "seed": args.seed,
        "profiles": {},
    }

    for prof_name, regimes in profiles.items():
        print(f"\n==================== {prof_name} (N={args.runs}) ====================")
        report["profiles"][prof_name] = {}
        for ctrl_name, ctrl_fn in controllers.items():
            print(f"\n--- {ctrl_name} ---")
            res = evaluate_suite(ctrl_fn, regimes, n_runs=args.runs, seed=args.seed)
            report["profiles"][prof_name][ctrl_name] = {}
            for r_name, m in res.items():
                mean_delay = round(statistics.mean(m.intervention_delays), 2) if m.intervention_delays else None
                delay_str = f"{mean_delay:.1f} steps" if mean_delay is not None else "N/A"
                print(
                    f"{r_name:21s} | Viol: {m.safety_violations:4d} | "
                    f"FP Trips: {m.false_positive_trips:4d} | "
                    f"Eff.Avail: {m.effective_availability*100:5.1f}% | "
                    f"Atten: {m.attenuated_steps:5d} | "
                    f"Escal: {m.escalations:5d} | Delay: {delay_str}"
                )
                report["profiles"][prof_name][ctrl_name][r_name] = {
                    "safety_violations": m.safety_violations,
                    "false_positive_trips": m.false_positive_trips,
                    "effective_availability_pct": round(m.effective_availability * 100, 2),
                    "attenuated_steps": m.attenuated_steps,
                    "escalations": m.escalations,
                    "mean_intervention_delay_steps": mean_delay,
                }

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
