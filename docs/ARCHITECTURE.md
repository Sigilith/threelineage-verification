Architecture — Verification Subset

1. Core Authentication and Replay Protection

Runtime environment secrets bind persistent stores to authenticated envelopes:

- GUARDIAN_HMAC_SECRET authenticates AuthSidecarManager and SQLiteReplayStore.
- VERIFIER_HMAC_SECRET authenticates VerifierAuthManager and ReplayProtectedHeartbeatVerifier.

ReplayProtectedHeartbeatVerifier does not parse an unauthenticated JSON-lines state file. Startup uses VerifierAuthManager.load_and_verify(). Each accepted heartbeat reloads the authenticated envelope under a process-level writer lock and commits a strictly higher generation through VerifierAuthManager.commit(). A failed integrity check rejects startup or the acceptance operation.

2. Elastic Autonomy Pipeline (Sigilith, Guardian, TraceGuard)

The runtime governance pipeline separates inviolable AXIOMOS binary safety perimeters from continuous authority attenuation inside remaining headroom:

- Sigilith (core/sigilith.py): Evaluates boundary headroom pressure (H), cumulative sequence drift (D), and action direction (Delta) to compute the continuous authority scalar alpha = f(H, D, Delta) across PERMIT_FULL, PERMIT_ATTENUATED, HOLD_ESCALATE, and FAIL_CLOSED.
- Guardian (core/transaction_authorization.py): Binds single-use permit nonces to the Sigilith autonomy envelope digest (alpha, permitted_delta, verdict) via SQLiteReplayStore.consume_attenuated(), rejecting replays and blocking actuation on HOLD_ESCALATE or FAIL_CLOSED.
- TraceGuard (core/traceguard.py): Appends every decision (action_id, permit_digest, H, D, Delta, alpha, verdict, permitted_delta) to an append-only SHA-256 hash-chained ledger (TraceGuardLedger) that fails closed if any historical entry is altered.

3. Assurance Boundaries

The .lock file is an adjacent local freshness marker, not an independent rollback-proof anchor. See PACKAGE-SCOPE.md and docs/THREAT_MODEL.md for the crash and host-compromise boundaries.
