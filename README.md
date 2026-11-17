# ThreeLineage Verification — RC2.2 candidate

**Status: NOT READY FOR PUBLIC RELEASE.** This is a focused developer verification package. It is not a security certification, independent audit, or proof of universal protection.

## Scope

This package contains the replay-store authentication modules, the telemetry replay verifier wired to `VerifierAuthManager`, the FIX1/FIX2 regression tests, the ADV-003 adversarial harnesses, evidence records, architecture/threat-model documentation, and release governance files. See `PACKAGE-SCOPE.md` for the complete allowlist and exclusions.

## Verification snapshot

The complete local release gate currently reports:

- Regression tests: **39 passed**.
- ADV-003-A2: **PASS**.
- ADV-003-B-R1A: **PASS** after telemetry persistence was routed through the authenticated envelope.

The file-level SHA-256 inventory is in `manifest.json`, with its own digest in `manifest.sha256`. The original pre-fix contradiction is retained at `evidence/contradicted-baseline-ADV-003-B-R1A.log`. Do not replace or rewrite that baseline record. The current pass does not erase the historical finding; it records that the tested remediation rejected the same tampering attempt.

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

See `docs/RELEASE_STATUS.md` before interpreting the verification results. Do not tag `v1.0.0` or publish until all blockers are closed and explicit release approval is given.
