# RC2.2 release status

**Decision: NOT READY FOR PUBLIC RELEASE.** The prior ADV-003-B-R1A contradiction has been remediated in the candidate, but release governance and additional fault-injection coverage remain open.

## Changes implemented

- Removed hardcoded fallback secrets. Missing or undersized `GUARDIAN_HMAC_SECRET` and `VERIFIER_HMAC_SECRET` values raise `ValueError`.
- `VerifierAuthManager.commit()` enforces a strictly increasing positive integer generation; generation rollback and same-generation commits are rejected.
- `_get_all_nonces()` surfaces SQLite read errors rather than converting them into an empty state.
- `SQLiteReplayStore.consume()` commits SQLite first and then replaces the separate authenticated sidecar. A per-store process lock serializes startup verification and consumption so ordinary concurrent writers do not observe the deliberate gap. A crash/failure in the gap leaves a detectable mismatch and requires administrative reconciliation.
- `ReplayProtectedHeartbeatVerifier` now loads and persists telemetry nonce history exclusively through `VerifierAuthManager`; it no longer reads or writes unauthenticated JSON-lines state.
- Telemetry state commits are serialized across processes with an adjacent writer lock and advance the authenticated generation.
- The ADV-003-B-R1A harness now requires a specific authenticated-load rejection and exits non-zero on a contradicted result.
- The original pre-integration contradicted output is preserved at `evidence/contradicted-baseline-ADV-003-B-R1A.log`.
- Added Apache-2.0 `LICENSE`, package scope, threat model boundaries and a private vulnerability-reporting policy.

## Verification observed in this working session

- FIX1/FIX2 plus RC2.2 telemetry integration and crash-boundary tests: **39 passed**.
- `ADV-003-A2.py`: **PASS**, exit 0.
- `ADV-003-B-R1A.py`: **PASS**, exit 0. The tampered envelope is rejected during authenticated loading; the original contradicted baseline remains archived separately.

These are developer-run checks in this environment, not independent replication or certification.

## Remaining release blockers

1. Configure and verify GitHub Private Vulnerability Reporting on the actual repository; designate and test a dedicated security contact if one is to be advertised.
2. Confirm ownership and redistribution rights for every included source file before publishing under Apache-2.0.
3. Extend fault-injection coverage to real `SIGKILL`/power-loss simulation where feasible, disk-full/permission failures, and multi-process stress beyond the current thread/process-lock regression coverage. A paired rollback demonstration is included and confirms the documented out-of-scope limitation.
4. Run the complete gate from a clean environment, record dependency/Python versions and the eventual Git source revision, and regenerate the final manifest after all edits.
5. Obtain explicit release approval before pushing or creating a public tag.

The adjacent `.lock` file is not an independent trust anchor. Paired rollback of both local files and full-host compromise remain out of scope absent external immutable storage or a hardware monotonic counter. The SQLite/sidecar crash window is intentionally fail-closed and requires administrative reconciliation.
