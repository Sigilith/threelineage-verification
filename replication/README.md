ThreeLineage Independent Replication Kit

Purpose

This kit enables an independent evaluator to reproduce the published v1.2.0 Pareto benchmark, release gate checks, and ADV-003, ADV-004, and ADV-005 verification harnesses in a clean environment without relying on developer host state or Git history.

Expected results and check definitions are provided strictly for independent comparison. Actual outputs from the evaluator's run must be recorded as observed and compared against expectations; observed failures or discrepancies must not be masked or altered to force a pass.

Directory Layout

- replication/environment/requirements.txt and setup.sh: Python runtime requirements and environment check.
- replication/benchmark/run_v1_2_0.py and expected_results.json: Reproduces the v1.2.0 Pareto benchmark and compares key metrics against expected baselines.
- replication/release_gate/run_replication.sh and verify_manifest.py: Runs clean-room manifest verification, pytest, unittest, and ADV-003 through ADV-005 harnesses, emitting a structured JSON result record.
- replication/evidence/expected_checks.json and result_schema.json: Expected harness/gate checks and schema for replication run results.
- replication/reports/TEMPLATE.md: Report template separating reproduced outputs from independent evaluator conclusions.
