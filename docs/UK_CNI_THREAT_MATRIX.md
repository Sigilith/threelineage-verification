ThreeLineage UK CNI Threat-to-Control Matrix

1. Purpose and Assurance Scope

This matrix maps UK Critical National Infrastructure (CNI) threat classes, NCSC Cyber Assessment Framework (CAF) v4.0 principles, and NCSC severe-threat operating principles to concrete components, implemented controls, and recorded verification evidence within threelineage-verification.

All mappings reflect verified repository behaviour within stated threat-model boundaries. They do not constitute third-party certification, regulatory approval, or proof of suitability for unverified physical OT/ICS deployment.

2. Architectural Separation of Duties

- AXIOMOS: Hard safety perimeter and authority policy invariants (fail-closed boundary enforcement).
- Sigilith (core/sigilith.py): Behavioural trajectory and autonomy-pressure engine computing continuous authority scalar alpha = f(H, D, Delta) across PERMIT_FULL, PERMIT_ATTENUATED, HOLD_ESCALATE, and FAIL_CLOSED.
- Guardian (core/transaction_authorization.py, core/auth_sidecar.py): Single-use permit replay enforcement binding nonces to attenuated envelope digests via SQLiteReplayStore.consume_attenuated().
- TraceGuard (core/traceguard.py, core/telemetry_verifier.py, core/verifier_auth.py): Authenticated telemetry replay verification and append-only SHA-256 hash-chained forensic evidence ledger.

3. Threat-to-Control and Evidence Matrix

Threat Class | Primary CAF v4.0 Alignment | ThreeLineage Component | Implemented Mechanism | Recorded Verification Evidence | Explicit Assurance Boundary
---|---|---|---|---|---
Identity and privilege misuse (unauthorised or excessive automated agent actions) | A1 Governance, B1 Policies, B2 Identity and Access | AXIOMOS, Guardian | Single-use cryptographic permit consumption bound to action digest and attenuated envelope (consume_attenuated) | tests/test_fix_tl_find_001.py, tests/test_sigilith_elastic_runtime.py, ADV-003-A2 (PASS) | Requires upstream enterprise IAM and key management; does not replace identity providers
Gradual operational drift and abnormal action sequences | A2 Risk Management, C2 Threat Hunting | Sigilith | Continuous autonomy scalar alpha = f(H, D, Delta) attenuating destabilizing trajectories while preserving stabilizing recovery | benchmarks/results/pareto_report_20261121T060323Z.md (0 violations across 60,000 trials), ADV-004-ELASTIC-PIPELINE (PASS) | Requires sector-validated operational baselines and OT safety engineering before physical actuation
Nuisance trip availability loss under benign volatility or telemetry jitter | D1 Response and Recovery (Safe Degradation) | Sigilith, Guardian | Smooth authority attenuation inside verified headroom; zero false-positive fail-closed trips under benign volatility | benchmarks/results/pareto_report_20261121T060323Z.md (0 fail-closed trips, 100.0% permit throughput in Regime A) | Software-layer authority regulation only; does not replace physical hardware interlocks
Telemetry spoofing, replay, and false-state injection | B3 Data Security, C1 Security Monitoring | TraceGuard | Ed25519 signature verification, drift window enforcement, and monotonic generation envelope (ReplayProtectedHeartbeatVerifier) | tests/test_fix2_tl_find_002.py, tests/test_telemetry_verifier_auth.py, ADV-003-B-R1A (PASS) | Adjacent .lock file is a local freshness marker, not a hardware-anchored rollback counter
Post-compromise audit tampering and disputed execution history | C1 Security Monitoring, D2 Lessons Learned | TraceGuard | Append-only SHA-256 hash-chained ledger recording (action_id, permit_digest, H, D, Delta, alpha, verdict, permitted_delta) | core/traceguard.py, tests/test_sigilith_elastic_runtime.py, ADV-004-ELASTIC-PIPELINE Stage 4 (PASS) | Host root compromise or stolen HMAC/signing keys remain outside local software boundary
Software and supply-chain artifact tampering | A4 Supply Chain, B4 System Security | ThreeLineage-Core | Deterministic file-level SHA-256 release inventory and pre-gate integrity verification | scripts/build_manifest.py, manifest.json, manifest.sha256, scripts/run_release_gate.sh | Covers packaged repository artifacts; external dependencies require separate SBOM and vulnerability scanning

4. Alignment with NCSC Severe-Threat Guidance (Operating Under Compromise)

- Situational awareness and monitoring: TraceGuard records every attenuated and escalated decision with headroom pressure (H), drift (D), direction (Delta), and alpha, enabling post-incident forensic reconstruction.
- Maintaining operations while threats persist: Sigilith bounds destabilizing agent authority via alpha attenuation rather than binary self-denial-of-service, preserving safe operational continuity during degraded or noisy telemetry conditions.
- Containment boundaries: AXIOMOS hard-bound checks and Guardian single-use nonces fail closed immediately upon state corruption or perimeter breach.

5. Outstanding Assurance Activities Required for CNI Pilot Evaluation

1. Independent external replication of the v1.2.0 Pareto benchmark and ADV-003/ADV-004 adversarial harnesses.
2. Integration with hardware-backed monotonic counters or external immutable log anchors to close local paired-file rollback risk.
3. Sector-specific OT/ICS safety-case integration (such as IEC 62443) prior to connecting SovereignExecutionGate to physical actuation paths.
