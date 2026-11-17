# Architecture — verification subset

```text
Runtime environment secrets
  ├── GUARDIAN_HMAC_SECRET ──> AuthSidecarManager ──> SQLiteReplayStore
  └── VERIFIER_HMAC_SECRET ──> VerifierAuthManager
                                  ▲
                                  │ canonical envelope + monotonic generation
                    ReplayProtectedHeartbeatVerifier

Regression tests and ADV-003 harnesses exercise these paths.
```

`ReplayProtectedHeartbeatVerifier` does not parse a raw JSON-lines state file. Startup uses `VerifierAuthManager.load_and_verify()`. Each accepted heartbeat reloads the authenticated envelope under a process-level writer lock and commits a strictly higher generation through `VerifierAuthManager.commit()`. A failed integrity check rejects startup or the acceptance operation.

The `.lock` file is an adjacent local freshness marker, not an independent rollback-proof anchor. See `PACKAGE-SCOPE.md` and `THREAT_MODEL.md` for the crash and host-compromise boundaries.
