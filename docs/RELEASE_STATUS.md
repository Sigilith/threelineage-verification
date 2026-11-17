# V1.0.0 release record and assurance status

**Release status: PUBLICLY RELEASED.** Version `V1.0.0` has been published in this repository. This document records the developer verification evidence and limitations associated with the release, together with assurance work that remains open. It is not a security certification or independent audit.

## Release identity and scope

The published artifact is a focused developer verification package, not the complete integrated ThreeLineage deployment. Its scope is defined in `PACKAGE-SCOPE.md`. The package covers replay-store authentication, the telemetry replay verifier integration, FIX1/FIX2 regression tests, ADV-003 adversarial harnesses, evidence records and supporting governance documentation.

The earlier RC2.2 candidate status and instruction not to tag `v1.0.0` or publish were pre-release instructions. They are superseded by the actual publication of V1.0.0 and are retained here only as release history, not as the current decision.

## Verification recorded for V1.0.0

The developer-run release gate recorded:

- FIX1/FIX2, RC2.2 telemetry integration and crash-boundary regression tests: **39 passed**.
- `ADV-003-A2.py`: **PASS**, exit 0.
- `ADV-003-B-R1A.py`: **PASS**, exit 0. The tampered envelope was rejected during authenticated loading; the original contradicted baseline remains archived separately.

These are developer-run results in the recorded environment. They are not independent replication, certification, or evidence that the wider integrated system has passed production assurance.

## Implemented behaviour recorded for the release

- Hardcoded fallback secrets were removed. Missing or undersized `GUARDIAN_HMAC_SECRET` and `VERIFIER_HMAC_SECRET` values raise `ValueError`.
- `VerifierAuthManager.commit()` enforces a strictly increasing positive integer generation; generation rollback and same-generation commits are rejected.
- `_get_all_nonces()` surfaces SQLite read errors rather than converting them into an empty state.
- `SQLiteReplayStore.consume()` commits SQLite first and then replaces the separate authenticated sidecar. A per-store process lock serializes startup verification and consumption so ordinary concurrent writers do not observe the deliberate gap. A crash/failure in the gap leaves a detectable mismatch and requires administrative reconciliation.
- `ReplayProtectedHeartbeatVerifier` loads and persists telemetry nonce history through `VerifierAuthManager`, rather than unauthenticated JSON-lines state.
- Telemetry state commits are serialized across processes with an adjacent writer lock and advance the authenticated generation.
- The ADV-003-B-R1A harness requires a specific authenticated-load rejection and exits non-zero on a contradicted result.
- The original pre-integration contradicted output is preserved at `evidence/contradicted-baseline-ADV-003-B-R1A.log`.

## Known limitations

1. SQLite and the separate `.auth.json` sidecar cannot be updated in one atomic filesystem operation. A crash or failure between the SQLite commit and sidecar replacement leaves a detectable mismatch and requires administrative reconciliation. This is fail-closed recovery, not proof of atomic commit.
2. The adjacent `.lock` freshness marker is not an independent trust anchor. Paired rollback of both local files is not prevented without external immutable storage or a hardware monotonic counter.
3. Full-host/privileged compromise, stolen runtime keys and compromised process memory are out of scope.
4. The recorded crash-boundary coverage does not establish physical power-loss durability or prove interruption at every point in the real commit/write/fsync path.
5. The package does not demonstrate kernel-enforced Linux isolation, namespace or seccomp enforcement, OS-level network policy, or Guardian/backend failure containment in the integrated deployment.

## Post-release assurance work — open

The following are follow-up assurance tasks, not statements that the published release is unpublished or invalid:

1. **Repository security reporting:** verify whether GitHub Private Vulnerability Reporting is enabled and reachable for this repository. No dedicated security email address is designated in this document.
2. **Rights and provenance:** retain evidence of ownership and redistribution rights for all included source files and dependencies.
3. **Fault injection:** extend coverage to interruption during the actual commit/write/fsync path, disk-full and permission failures, and genuine multi-process stress. Distinguish process-exit recovery from physical power-loss testing.
4. **Reproduction:** rerun the release gate from a clean environment and record the exact Python/dependency versions and source revision used for any subsequent verification.
5. **Integrated deployment assurance:** separately test Guardian and backend failure behaviour, Linux kernel isolation and OS-enforced network restrictions. The verification subset does not establish these properties.
6. **Independent assurance:** obtain external reproduction and technical review; record findings and remediation separately from internal test results.

## Provenance and manifest handling

The published manifest and its digest are historical release evidence. Do not silently regenerate, replace or rewrite them as part of documentation corrections. Any later release or documentation snapshot should identify its own source revision and manifest explicitly. Preserve the original contradicted baseline evidence unchanged.
