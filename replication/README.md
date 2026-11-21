ThreeLineage Independent Replication Kit

Canonical evaluator snapshot

This handoff is pinned to main at commit f5c7f94176f5b852d1a64af19b67e2f2462bfb98. The matching clean archive is threelineage-verification-main-f5c7f94.tar.gz and its checksum sidecar is threelineage-verification-main-f5c7f94.tar.gz.sha256. Verify the sidecar before extraction. Do not silently replace this snapshot with a later main revision.

Purpose

This kit enables an independent evaluator to reproduce the published v1.2.0 Pareto benchmark, release gate checks, and ADV-003, ADV-004, and ADV-005 verification harnesses in a clean environment without relying on developer host state or Git history.

Expected results and check definitions are provided strictly for independent comparison. Actual outputs from the evaluator's run must be recorded as observed and compared against expectations; observed failures or discrepancies must not be masked or altered to force a pass.

Directory Layout

- replication/environment/requirements.txt and setup.sh: Python runtime requirements and environment check.
- replication/benchmark/run_v1_2_0.py and expected_results.json: Reproduces the v1.2.0 Pareto benchmark and compares key metrics against expected baselines.
- replication/release_gate/run_replication.sh and verify_manifest.py: Runs clean-room manifest verification, pytest, unittest, and ADV-003 through ADV-005 harnesses, emitting a structured JSON result record.
- replication/evidence/expected_checks.json and result_schema.json: Expected harness/gate checks and schema for replication run results.
- replication/reports/TEMPLATE.md: Report template separating reproduced outputs from independent evaluator conclusions and recording the pinned source commit.

Participation

Use the repository's Independent Replication Registration issue template to register one evaluator or independent evaluation team per issue. Registration is not evidence of a test run or successful reproduction. Update the issue status only when the corresponding stage has actually been reached.
