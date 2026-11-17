# Threat model — RC2.2 candidate

## Assets
- consumed-approval nonce records in SQLite;
- telemetry verifier nonce/timestamp history;
- verifier state envelope and local generation marker;
- runtime HMAC keys and reproducible verification evidence.

## Adversary capabilities considered
- read, modify, insert or delete local persistence records;
- substitute historical telemetry nonces in the persisted envelope;
- restore stale local state while leaving a newer adjacent generation marker;
- remove or corrupt authentication metadata;
- provide a missing, malformed or incorrect runtime HMAC secret;
- trigger ordinary SQLite read/write failures or terminate a process during persistence.

## Controls in this candidate
- HMAC-authenticated canonical verifier-state envelope;
- generation strictly increases on each telemetry state commit;
- telemetry verifier loads and commits exclusively through `VerifierAuthManager`;
- missing/invalid runtime secrets raise `ValueError`; no source-code fallback credentials;
- SQLite read errors are surfaced rather than converted into empty state;
- integrity failures reject state loading/consumption rather than silently healing it.

## Explicit architectural boundaries

### SQLite / sidecar crash-consistency window

SQLite and the adjacent `.auth.json` sidecar are separate files. POSIX filesystem operations do not provide a single atomic transaction spanning both files. The store commits the SQLite transaction and then atomically replaces the sidecar. A hard power loss or `SIGKILL` strictly between the SQLite commit and the `os.replace()` of the sidecar leaves a detectable state-hash mismatch. On the next access, the implementation must fail closed. Recovery requires administrative reconciliation from trusted evidence; there is no silent auto-healing. This is an intentional fail-closed recovery boundary, not a claim of cross-file crash atomicity.

### Adjacent `.lock` freshness marker

The verifier `.lock` marker resides on the same ordinary filesystem as the authenticated state envelope. The state envelope and marker must report exactly the same generation; a mismatch in either direction fails closed and requires administrative reconciliation. A process interruption between replacing the state envelope and replacing the marker can therefore leave a split pair. The marker can detect partial state truncation, missing components and unanchored state changes while it remains intact. It is not an independent trust anchor. An attacker with unconstrained write access who can restore both files simultaneously can restore an older valid pair. That paired rollback and full-host compromise are out of scope unless an external immutable store, remote witness or hardware monotonic counter is deployed.

## Security claim boundary

Included tests demonstrate only the observed behaviour of this code, under the documented test environment and commands. A passing adversarial harness is not independent assessment, certification, proof of complete threat coverage or proof against all attackers. No claim is made against compromised process memory, privileged host access, stolen runtime keys, or rollback of both local state and marker.
