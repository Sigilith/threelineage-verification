#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

export EVALUATOR="${EVALUATOR:-independent-evaluator}"
export RUNS="${RUNS:-100}"
export SEED="${SEED:-2026}"
export OUT_DIR="${OUT_DIR:-$REPO_ROOT/replication_run_output}"
export SOURCE_COMMIT_OR_SNAPSHOT="${SOURCE_COMMIT_OR_SNAPSHOT:-$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || printf 'unknown')}"
export SOURCE_ARCHIVE_SHA256="${SOURCE_ARCHIVE_SHA256:-}"

mkdir -p "$OUT_DIR"
export CLEAN_TREE="$(mktemp -d)"
trap 'rm -rf "$CLEAN_TREE"' EXIT

cp -a "$REPO_ROOT/." "$CLEAN_TREE/"
rm -rf "$CLEAN_TREE/.git"
find "$CLEAN_TREE" -type d \( -name "__pycache__" -o -name ".pytest_cache" \) -exec rm -rf {} +

export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH="$CLEAN_TREE"

python3 "$CLEAN_TREE/replication/release_gate/verify_manifest.py" \
  --root "$CLEAN_TREE" \
  --output-json "$OUT_DIR/manifest_verification.json"

(
  cd "$CLEAN_TREE"
  bash scripts/run_release_gate.sh
  python3 -m unittest discover -v
) > "$OUT_DIR/release_gate_and_unittest.log" 2>&1

python3 - << 'PYEOF'
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import subprocess
import sys

out_dir = Path(os.environ["OUT_DIR"])
clean_tree = Path(os.environ["CLEAN_TREE"])
gate_log = (out_dir / "release_gate_and_unittest.log").read_text(encoding="utf-8")
manifest_res = json.loads((out_dir / "manifest_verification.json").read_text(encoding="utf-8"))

checks = {
    "manifest_integrity": "PASS" if manifest_res.get("verified") else "FAIL",
    "release_gate_script": "PASS" if "passed in" in gate_log else "FAIL",
    "unittest_suite": "PASS" if ("\nOK\n" in gate_log or gate_log.strip().endswith("OK")) else "FAIL",
    "adv_003_a2": "PASS" if "ADV-003-A2 COMPLETE. VERDICT: PASS" in gate_log else "FAIL",
    "adv_003_b_r1a": "PASS" if "ADV-003-B-R1A COMPLETE. VERDICT: PASS" in gate_log else "FAIL",
    "adv_004_elastic_pipeline": "PASS" if "ADV-004-ELASTIC-PIPELINE COMPLETE. VERDICT: PASS" in gate_log else "FAIL",
    "adv_005_delegation_chain": "PASS" if "ADV-005-DELEGATION-CHAIN COMPLETE. VERDICT: PASS" in gate_log else "FAIL",
}

expected_checks = json.loads((clean_tree / "replication/evidence/expected_checks.json").read_text(encoding="utf-8"))
all_checks_match = all(checks.get(k) == v for k, v in expected_checks["expected_verdicts"].items()) and all(
    v == "PASS" for v in checks.values()
)

bench_out = out_dir / "benchmark_comparison.json"
bench_proc = subprocess.run(
    [
        sys.executable,
        str(clean_tree / "replication/benchmark/run_v1_2_0.py"),
        "--runs",
        os.environ.get("RUNS", "100"),
        "--seed",
        os.environ.get("SEED", "2026"),
        "--output-json",
        str(bench_out),
    ],
    cwd=str(clean_tree),
    capture_output=True,
    text=True,
)
bench_data = json.loads(bench_out.read_text(encoding="utf-8")) if bench_out.exists() else {"status": "ERROR", "stderr": bench_proc.stderr}

overall_status = "REPRODUCED_AS_EXPECTED" if (all_checks_match and bench_data.get("status") == "MATCHED_EXPECTED") else "OBSERVED_DIFFERENCE_OR_FAILURE"

summary = {
    "replication_id": f"rep-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}",
    "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    "evaluator_name": os.environ.get("EVALUATOR", "independent-evaluator"),
    "environment": {
        "python_version": sys.version,
        "platform": platform.platform(),
        "machine": platform.machine(),
    },
    "source_commit_or_snapshot": os.environ.get("SOURCE_COMMIT_OR_SNAPSHOT") or "not-provided",
    "source_archive_sha256": os.environ.get("SOURCE_ARCHIVE_SHA256") or None,
    "manifest_verification": manifest_res,
    "checks": checks,
    "benchmark_comparison": bench_data,
    "overall_reproduction_status": overall_status,
    "evaluator_notes": "Recorded directly from observed clean-room execution; compare against expected baselines before drawing independent assurance conclusions.",
}

(out_dir / "replication_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(json.dumps(summary, indent=2, sort_keys=True))
sys.exit(0 if overall_status == "REPRODUCED_AS_EXPECTED" else 1)
PYEOF
