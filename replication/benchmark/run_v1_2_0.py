#!/usr/bin/env python3
"""Independent runner and comparator for the ThreeLineage v1.2.0 Pareto benchmark."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _load_expected() -> dict[str, Any]:
    expected_path = Path(__file__).resolve().parent / "expected_results.json"
    return json.loads(expected_path.read_text(encoding="utf-8"))


def _extract_metrics(payload: Any) -> dict[str, Any]:
    """Extract normalized invariant and availability metrics from v1.2.0 benchmark output."""
    violations = 0
    escapes = 0
    benign_elastic_trips: list[int] = []
    benign_elastic_throughput_pct: list[float] = []
    regime_entries = 0

    if isinstance(payload, dict) and isinstance(payload.get("profiles"), dict):
        for _, ctrls in payload["profiles"].items():
            if not isinstance(ctrls, dict):
                continue
            for ctrl_name, regimes in ctrls.items():
                if not isinstance(regimes, dict):
                    continue
                for regime_name, metrics in regimes.items():
                    if not isinstance(metrics, dict):
                        continue
                    regime_entries += 1
                    safety = metrics.get("safety_metrics", {})
                    if isinstance(safety, dict):
                        violations += int(safety.get("hard_invariant_violations", 0) or 0)
                        escapes += int(safety.get("constraint_escapes", 0) or 0)

                    if "elastic" in str(ctrl_name).lower() and (
                        "benign" in str(regime_name).lower() or str(regime_name).startswith("A_")
                    ):
                        if isinstance(safety, dict) and "fail_closed_activations" in safety:
                            benign_elastic_trips.append(int(safety["fail_closed_activations"]))
                        if "permit_throughput_pct" in metrics and metrics["permit_throughput_pct"] is not None:
                            benign_elastic_throughput_pct.append(float(metrics["permit_throughput_pct"]))

    return {
        "regime_entries": regime_entries,
        "total_violations": violations,
        "total_escapes": escapes,
        "benign_elastic_fail_closed_trips": benign_elastic_trips,
        "benign_elastic_permit_throughput_pct": benign_elastic_throughput_pct,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run and compare v1.2.0 Pareto benchmark.")
    parser.add_argument("--runs", type=int, default=10000)
    parser.add_argument("--seed", type=int, default=2026)
    parser.add_argument("--output-json", type=Path, required=True)
    args = parser.parse_args()

    expected = _load_expected()
    harness_path = ROOT / "benchmarks" / "pareto_harness.py"
    if not harness_path.exists():
        raise FileNotFoundError(f"Missing benchmark harness: {harness_path}")

    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    raw_out = args.output_json.parent / "pareto_raw_output.json"

    cmd = [sys.executable, str(harness_path), "--runs", str(args.runs), "--seed", str(args.seed)]
    proc = subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True)

    parsed_data: Any = None
    results_dir = ROOT / "benchmarks" / "results"
    if results_dir.exists():
        for candidate in sorted(results_dir.glob("pareto_benchmark_*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
            try:
                obj = json.loads(candidate.read_text(encoding="utf-8"))
                integ = obj.get("benchmark_integrity", {}) if isinstance(obj, dict) else {}
                seed_ok = (integ.get("random_seed") == args.seed or integ.get("seed") == args.seed)
                runs_ok = (integ.get("runs_per_regime") == args.runs or integ.get("runs") == args.runs)
                if seed_ok and runs_ok:
                    parsed_data = obj
                    break
            except Exception:
                continue

    if parsed_data is None:
        parsed_data = {"stdout": proc.stdout, "stderr": proc.stderr}

    serialized = json.dumps(parsed_data, indent=2, sort_keys=True) + "\n"
    raw_out.write_text(serialized, encoding="utf-8")
    artifact_sha256 = hashlib.sha256(raw_out.read_bytes()).hexdigest()

    extracted = _extract_metrics(parsed_data)
    expected_trips = int(expected.get("expected_benign_elastic_fail_closed_trips", 0))
    expected_thru = float(expected.get("expected_benign_elastic_permit_throughput_pct", 100.0))

    comparisons = {
        "harness_exit_zero": proc.returncode == 0,
        "has_regime_entries": extracted["regime_entries"] > 0,
        "violations_zero": extracted["total_violations"] == 0 if expected.get("expected_zero_violation_invariant") else True,
        "escapes_zero": extracted["total_escapes"] == 0 if expected.get("expected_zero_escape_invariant") else True,
        "benign_elastic_trips_match": all(t == expected_trips for t in extracted["benign_elastic_fail_closed_trips"]),
        "benign_elastic_throughput_match": all(
            abs(p - expected_thru) < 1e-6 for p in extracted["benign_elastic_permit_throughput_pct"]
        ),
    }
    matched_expected = all(comparisons.values())

    report = {
        "benchmark_version": expected["benchmark_version"],
        "runs_per_regime": args.runs,
        "seed": args.seed,
        "raw_output_path": str(raw_out),
        "raw_output_sha256": artifact_sha256,
        "extracted_metrics": extracted,
        "expected_baseline": expected,
        "comparisons": comparisons,
        "status": "MATCHED_EXPECTED" if matched_expected else "DEVIATED_FROM_EXPECTED",
    }
    args.output_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if matched_expected else 1


if __name__ == "__main__":
    sys.exit(main())
