# ThreeLineage V1.0.0 – 10k-Trial Safety–Availability Pareto Benchmark Reproducibility Checklist

Use this checklist before publishing benchmark results, attaching them to a paper, submitting them to a sandbox, or presenting them during technical review.

## 1. Repository Integrity
- [ ] Repository name recorded.
- [ ] Git remote URL recorded.
- [ ] Branch name recorded.
- [ ] Commit hash recorded.
- [ ] Working tree clean before execution.

## 2. Benchmark Version
- [ ] Harness version recorded.
- [ ] Scenario profile recorded.
- [ ] Trial count recorded.
- [ ] Random seed recorded.
- [ ] Elastic/Binary model version recorded.

## 3. Platform Metadata
- [ ] Operating system recorded.
- [ ] Kernel version recorded.
- [ ] CPU model recorded.
- [ ] RAM capacity recorded.
- [ ] Python version recorded.

## 4. Dependency Verification
- [ ] `requirements.txt` version recorded.
- [ ] Installed package manifest exported (`dependencies.txt`).
- [ ] Dependency hashes retained.

## 5. Scenario Definition Verification
### A. Benign Volatility
- [ ] Load spikes enabled.
- [ ] Sensor jitter enabled.
- [ ] Communication delay enabled.
- [ ] No malicious actions injected.
- [ ] Expected violations = 0.

### B. Slow Drift
- [ ] Gradual parameter drift enabled.
- [ ] Drift escalation schedule recorded.
- [ ] Drift injection reproducible.
- [ ] Expected violations = 0.

### C. Adversarial Drift
- [ ] Coordinated drift injection enabled.
- [ ] Multi-node coupling enabled.
- [ ] Cascade pressure enabled.
- [ ] Expected violations = 0.

## 6. Control Model Verification
### Binary_V1
- [ ] Nominal state enabled.
- [ ] Fail-closed logic enabled.
- [ ] No attenuation path present.

### Elastic_V2
- [ ] `PERMIT_FULL` enabled.
- [ ] `PERMIT_ATTENUATED` enabled.
- [ ] `HOLD_ESCALATE` enabled.
- [ ] `FAIL_CLOSED` enabled.
- [ ] Sigilith autonomy-scalar enabled.
- [ ] Guardian permit attenuation enabled.
- [ ] TraceGuard telemetry logging enabled.

## 7. Artifact Integrity
- [ ] SHA-256 recorded.
- [ ] SHA-256 verified.
- [ ] Results directory archived.

## 8. Core Metrics Verification
### Safety
- [ ] Boundary violations recorded (`Violations = 0`).
- [ ] Hard invariant breaches recorded.
- [ ] Unexpected execution escapes recorded.

### Availability
- [ ] Effective availability recorded.
- [ ] Task completion rate recorded.
- [ ] Escalation impacts recorded.

### Governance
- [ ] Permit count recorded.
- [ ] Attenuation count recorded.
- [ ] Hold count recorded.
- [ ] Fail-closed count recorded.

### Timing
- [ ] Average intervention delay recorded.
- [ ] Median delay recorded.
- [ ] Maximum delay recorded.

## 9. Safety–Availability Claims
### Allowed Claims
- [ ] "No hard-invariant violations observed."
- [ ] "False-positive trips reduced from X to Y."
- [ ] "Mean intervention delay reduced from X to Y."
- [ ] "Availability increased from X to Y."

### Not Allowed Claims
- [ ] Production certification.
- [ ] Regulatory approval.
- [ ] Operational deployment fitness.
- [ ] Universal safety guarantees.

## 10. Independent Reproduction Package
- [ ] Benchmark source code.
- [ ] Configuration files.
- [ ] Scenario definitions.
- [ ] Random seed.
- [ ] Dependency manifest.
- [ ] Artifact hash.
- [ ] Commit hash.
- [ ] Reproduction instructions.

## 11. Publication Verification Statement
All benchmark results were generated from version-controlled source code using a documented execution environment, fixed scenario definitions, recorded random seeds, and cryptographically hashed output artifacts. Results demonstrate behaviour within the tested benchmark environment only and should not be interpreted as certification, regulatory approval, or evidence of production deployment suitability.
