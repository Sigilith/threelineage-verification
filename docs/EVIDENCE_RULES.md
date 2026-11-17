# Evidence rules

1. Record exact source revision, package manifest hash, Python version, dependency versions, command, working directory and exit status.
2. Preserve complete stdout/stderr and generated harness artefacts; redact secrets and sensitive host paths.
3. A harness is PASS only when its internal verdict is PASS and its process exit status is zero.
4. A process exit status of zero does not override an internal `CONTRADICTED` verdict.
5. Preserve the pre-fix ADV-003-B-R1A contradiction as a separate immutable baseline evidence file. Never rewrite it to reflect the remediation.
6. Record remediation results under a new RC2.2 evidence file and manifest identity.
7. Separate regression-test results from adversarial-harness results.
8. Distinguish developer-run checks from independent replication, penetration assessment and certification.
9. Never include live secrets, private keys, personal paths or production data in evidence.
