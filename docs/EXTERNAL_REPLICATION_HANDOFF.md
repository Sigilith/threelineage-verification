ThreeLineage External Replication Handoff Guide

1. Purpose

This guide provides step-by-step instructions for an independent evaluator to reproduce the ThreeLineage verification suite in a clean environment without relying on developer host state or Git history, and record findings using replication/reports/TEMPLATE.md.

2. Pre-Run Evaluator Checklist

- Obtain a clean repository snapshot or archive without .git and without pre-existing __pycache__ or .pytest_cache directories.
- Record host environment metadata (OS, kernel, architecture, Python version, and installed package versions).
- Confirm that expected baselines in replication/benchmark/expected_results.json and replication/evidence/expected_checks.json are used solely for comparison, never to alter observed outputs.

3. Clean-Room Execution Steps

1. Prepare environment:
   bash replication/environment/setup.sh
2. Run the replication workflow into an isolated output directory:
   OUT_DIR=/tmp/threelineage_rep_out EVALUATOR="your-name-or-org" RUNS=100 SEED=2026 bash replication/release_gate/run_replication.sh
3. For a full 10,000-run v1.2.0 benchmark comparison (optional, longer runtime):
   python3 replication/benchmark/run_v1_2_0.py --runs 10000 --seed 2026 --output-json /tmp/threelineage_rep_out/v1_2_0_full.json

4. Reporting Rules

- Copy replication/reports/TEMPLATE.md and fill in observed manifest verification results, pytest/unittest counts, ADV-003 through ADV-005 verdicts, and benchmark comparisons exactly as executed.
- Keep reproduced outputs separate from independent evaluator conclusions and explicitly note scope boundaries (such as software-only replication vs. hardware-anchored trust or sector OT safety assurance).
