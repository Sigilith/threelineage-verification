Independent Replication Report — ThreeLineage Verification

Canonical handoff snapshot (do not substitute a later commit without recording it as a separate evaluation):
- Repository: Sigilith/threelineage-verification
- Branch at snapshot creation: main
- Source commit: f5c7f94176f5b852d1a64af19b67e2f2462bfb98
- Archive: threelineage-verification-main-f5c7f94.tar.gz
- Archive SHA-256 (copy the observed value from the verified sidecar; do not infer it):

1. Evaluator and Environment Metadata

- Evaluator name / organisation:
- Date and UTC timestamp of replication run:
- Host OS, kernel, CPU architecture, and Python version:
- Installed package versions:
- Confirmation of clean-room execution without .git or pre-existing caches:

2. Reproduced Outputs vs. Expected Baselines

Record observed results directly from execution without modifying outputs to match expectations.

- Archive checksum verification result:
- Manifest verification (checked files, manifest SHA-256, mismatches):
- Pytest and unittest results:
- ADV-003-A2 observed verdict and notes:
- ADV-003-B-R1A observed verdict and notes:
- ADV-004-ELASTIC-PIPELINE observed verdict and notes:
- ADV-005-DELEGATION-CHAIN observed verdict and notes:
- v1.2.0 Pareto benchmark parameters (runs per regime, seed) and observed vs. expected metrics:

3. Observed Discrepancies, Warnings, or Environment Constraints

Document any differences from expected baselines, timing/resource constraints, or skipped/failed checks.

4. Independent Evaluator Conclusions (Separate from Reproduced Facts)

State only what this independent run supports and what remains outside its scope (such as external safety engineering, hardware root-of-trust anchoring, or production deployment approval).

5. Evaluator Declaration

- [ ] I confirm this report records outputs observed in my own environment.
- [ ] I have not altered expected results or suppressed failures to obtain a pass.
- [ ] I understand that software replication does not establish hardware-backed trust, live OT/ICS safety assurance, certification, or regulatory approval.
