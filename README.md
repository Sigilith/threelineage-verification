# ThreeLineage Verification — V1.0.0

**Status: PUBLIC RELEASED.** Version `V1.0.0` is published in this repository. This is a focused developer verification package. Publication does not constitute a security certification, independent audit, or proof of universal protection.

## Scope

This package contains the replay-store authentication modules, the telemetry replay verifier wired to `VerifierAuthManager`, the FIX1/FIX2 regression tests, the ADV-003 adversarial harnesses, evidence records, architecture/threat-model documentation, and release governance files. See `PACKAGE-SCOPE.md` for the complete allowlist and exclusions.

This is the verification subset only; it is not the complete integrated ThreeLineage deployment. It does not by itself demonstrate kernel-enforced execution isolation or independent assurance of the wider system.

## V1.0.0 verification record

The developer-run release gate recorded:

- Regression tests: **39 passed**.
- ADV-003-A2: **PASS**.
- ADV-003-B-R1A: **PASS** after telemetry persistence was routed through the authenticated envelope.

These results are internal developer-run checks, not independent replication, certification, or a production security guarantee. See `docs/RELEASE_STATUS.md` for the release record, limitations and post-release assurance work.

The file-level SHA-256 inventory for the published verification package is in `manifest.json`, with its digest in `manifest.sha256`. The original pre-fix contradiction is retained at `evidence/contradicted-baseline-ADV-003-B-R1A.log`. Do not replace or rewrite that baseline record. The current pass does not erase the historical finding; it records that the tested remediation rejected the same tampering attempt.

## Run

Python 3.11+ and the dependencies in `requirements.txt` are required.

```sh
python -m pip install -r requirements.txt
bash scripts/run_release_gate.sh
```

The release runner creates ephemeral test-only secrets when the caller has not supplied them. Production modules have no fallback credentials. Never reuse test secrets in a deployment.

## Explicit limitations

- SQLite and its `.auth.json` sidecar cannot be updated in one atomic filesystem operation. A crash after the SQLite commit and before sidecar replacement causes a detectable mismatch and fail-closed administrative recovery.
- The verifier `.lock` freshness marker is adjacent to the state envelope. An attacker able to restore both files can roll back the pair. No protection against this paired rollback is claimed without an external immutable anchor or hardware monotonic counter.
- No claim is made against privileged host compromise, stolen runtime keys, or compromised process memory.
- This package does not establish real Linux namespace/seccomp isolation, OS-enforced network restrictions, or Guardian/backend failure containment for the integrated runtime.
- The recorded tests do not establish physical power-loss durability or prove every interruption point during a real ledger commit.

## Release and assurance status

V1.0.0 has been published. The earlier RC2.2 candidate wording and pre-publication instruction not to tag or publish are historical and superseded by that release. Outstanding assurance work remains; publication must not be interpreted as closure of those gaps. See `docs/RELEASE_STATUS.md` for details.
