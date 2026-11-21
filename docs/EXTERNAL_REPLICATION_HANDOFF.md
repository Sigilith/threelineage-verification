ThreeLineage External Replication Handoff Guide

1. Purpose and Pinned Snapshot

This guide provides step-by-step instructions for an independent evaluator to reproduce the ThreeLineage verification suite in a clean environment without relying on developer host state or Git history, and record findings using replication/reports/TEMPLATE.md.

The canonical evaluator reference for this handoff is:

- Repository: https://github.com/Sigilith/threelineage-verification
- Branch at snapshot creation: main
- Source commit: f5c7f94176f5b852d1a64af19b67e2f2462bfb98
- Archive: threelineage-verification-main-f5c7f94.tar.gz
- Checksum sidecar: threelineage-verification-main-f5c7f94.tar.gz.sha256

Do not silently substitute a later main commit or a rebuilt archive. If a defect requires a corrected snapshot, publish it as a separately identified version and preserve this reference.

2. Pre-Run Evaluator Checklist

- Obtain the exact archive and its matching checksum sidecar.
- Verify the archive before extraction:
  sha256sum -c threelineage-verification-main-f5c7f94.tar.gz.sha256
- Extract into a clean directory; the evaluator package must not depend on .git or pre-existing __pycache__ or .pytest_cache directories.
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
- Record the exact source commit and archive SHA-256 in the report. The source commit for this handoff is f5c7f94176f5b852d1a64af19b67e2f2462bfb98.
- Keep reproduced outputs separate from independent evaluator conclusions and explicitly note scope boundaries (such as software-only replication vs. hardware-anchored trust or sector OT safety assurance).
- Do not change expected baselines or suppress failed, skipped, or discrepant results.
