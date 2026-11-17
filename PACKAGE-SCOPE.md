# Package scope — ThreeLineage verification candidate RC2.2

## Included

- `core/auth_sidecar.py`: HMAC sidecar authentication for SQLite replay state.
- `core/transaction_authorization.py`: SQLite-backed consumed-approval replay store.
- `core/verifier_auth.py`: canonical authenticated verifier-state envelope and local generation marker.
- `core/telemetry_verifier.py`: heartbeat replay verifier; all persistent nonce state is routed through `VerifierAuthManager`.
- `tests/`: FIX1/FIX2 regression coverage, RC2.2 telemetry integration tests, and crash-boundary/paired-rollback demonstrations.
- `harnesses/`: supplied ADV-003-A2 and ADV-003-B-R1A adversarial harnesses.
- `evidence/`: original contradicted pre-integration ADV-003-B-R1A output and current release-gate logs.
- Root governance and reproducibility files: architecture, threat model, evidence rules, security policy, licence, manifest and runner.

## Excluded

Unrelated application/business logic, unrelated research or proprietary IP, backups, bytecode, caches, local environment files, credentials, production values, developer home paths and development-only artefacts.

## Persistence and recovery boundaries

SQLite and its `.auth.json` sidecar are separate filesystem objects and cannot be committed in one atomic filesystem operation. The implementation commits the SQLite transaction and then publishes the sidecar. A hard power loss or process termination strictly between those operations can leave a state/sidecar mismatch. On the next operation this must fail closed and require administrative reconciliation; automatic repair or silent reinitialization is not supported.

The verifier `.lock` generation marker is adjacent to the authenticated state envelope on the same filesystem. It can detect missing, partial, or unanchored state changes when the marker remains intact. It cannot prevent an attacker with sufficient write access from restoring both files to a previously valid pair. Such full-host or paired-file rollback is out of scope without an external immutable anchor or hardware monotonic counter.

This package does not claim atomicity across separate files, protection against privileged host compromise, independent certification, or universal security.
