ThreeLineage Verification — V1.0.0

Status: PUBLIC RELEASE — V1.0.0

ThreeLineage Verification V1.0.0 is a published, executable developer verification package. It provides reproducible tests and supporting evidence for selected authentication, telemetry-integrity, replay-resistance and adversarial verification controls within the ThreeLineage architecture.

This release establishes a working verification artefact with a documented test record and explicit technical boundaries. It does not claim independent security certification or universal protection.

1. Purpose

ThreeLineage is designed around distinct, complementary responsibilities:

- Sigilith — structural analysis.
- AXIOMOS — authority and policy governance.
- Guardian — execution-boundary enforcement.
- TraceGuard — evidence recording and integrity.
- ThreeLineage — integration of these independent frameworks.

This repository publishes a focused verification package supporting selected controls. It is not a distribution of the complete integrated ThreeLineage runtime.

2. Package scope

The published package contains:

- Replay-store authentication modules.
- Telemetry replay verification integrated with "VerifierAuthManager".
- FIX1 and FIX2 regression tests.
- ADV-003 adversarial test harnesses.
- Verification evidence and supporting records.
- Architecture and threat-model documentation.
- Release governance and package-integrity files.

The authoritative file allowlist and exclusions are documented in "PACKAGE-SCOPE.md".

3. V1.0.0 verification results

The recorded developer-run release gate produced the following results:

Verification item| Recorded result
Regression test suite| 39 passed
ADV-003-A2| PASS
ADV-003-B-R1A| PASS

ADV-003-B-R1A passed after telemetry persistence was routed through the authenticated envelope.

These results demonstrate successful execution of the specified internal verification checks. They must not be interpreted as independent replication, third-party certification or proof of the security of every component in the wider architecture.

The release record, test interpretation and outstanding assurance work are documented in "docs/RELEASE_STATUS.md".

4. Package integrity and historical evidence

The published package includes a file-level SHA-256 inventory in "manifest.json", with its corresponding digest in "manifest.sha256".

The original pre-fix contradictory finding is preserved in:

"evidence/contradicted-baseline-ADV-003-B-R1A.log"

This historical evidence is intentionally retained. It must not be overwritten or rewritten.

The subsequent PASS records the result of the tested remediation against the same tampering scenario. It does not erase or retrospectively alter the original finding.

5. Installation and execution

Requirements: Python 3.11 or later and the dependencies listed in "requirements.txt".

Run the verification suite:

python -m pip install -r requirements.txt
bash scripts/run_release_gate.sh

The release runner generates ephemeral test-only secrets when the caller has not supplied them. Production modules do not provide fallback credentials.

Test-generated secrets must never be reused in a production deployment.

6. Security boundaries and limitations

The following boundaries are explicit:

Persistence atomicity

SQLite and its ".auth.json" sidecar cannot be updated through a single atomic filesystem operation. A crash after the SQLite commit but before sidecar replacement can produce a detectable mismatch requiring fail-closed administrative recovery.

Rollback protection

The verifier ".lock" freshness marker is stored adjacent to the state envelope. An attacker able to restore both files can roll back the pair. Protection against this paired rollback is not claimed without an external immutable anchor or hardware monotonic counter.

Host and runtime compromise

This package does not claim protection against privileged host compromise, stolen runtime keys or compromised process memory.

Operating-system enforcement

This package does not establish kernel-enforced Linux namespace or seccomp isolation, operating-system-enforced network restrictions, or Guardian/backend failure containment across the complete integrated runtime.

Durability

The recorded tests do not establish physical power-loss durability or prove every possible interruption point during a real ledger commit.

These limitations define the assurance boundary of this published package. They do not invalidate the recorded verification results within their stated scope.

7. Release status

V1.0.0 is publicly released.

The earlier RC2.2 candidate wording and pre-publication instruction not to tag or publish are historical and superseded by this release.

The published package is an executable verification artefact with recorded internal test results. Further independent replication, external security assessment and wider integrated-runtime assurance remain separate activities.

Publication establishes the availability of this version and its accompanying evidence; it does not imply that every outstanding assurance activity has been completed.

For the detailed release record and outstanding assurance boundaries, see "docs/RELEASE_STATUS.md".

---

ThreeLineage Verification — V1.0.0
Public release | Reproducible developer verification | Documented assurance boundaries

8. Independent replication register — snapshot f5c7f94

The current independent-evaluation reference snapshot is pinned to:

`f5c7f94176f5b852d1a64af19b67e2f2462bfb98`

This snapshot is later than the V1.0.0 release record above. It includes the subsequent verification work on `main`; it does not rewrite the historical V1.0.0 results.

Evaluator participation is tracked through one GitHub issue per evaluator or independent evaluation team. Register using the [Independent Replication Registration issue template](https://github.com/Sigilith/threelineage-verification/issues/new?template=replication-registration.md).

Live participation counts (open registration issues, grouped by the current issue-title status):

| Stage | Live count |
|---|---|
| Registered | ![Registered](https://img.shields.io/github/issues-search/Sigilith/threelineage-verification?query=is%3Aissue%20is%3Aopen%20in%3Atitle%20%22%5BReplication%3A%20Registered%5D%22&label=registered) |
| Testing started | ![Testing](https://img.shields.io/github/issues-search/Sigilith/threelineage-verification?query=is%3Aissue%20is%3Aopen%20in%3Atitle%20%22%5BReplication%3A%20Testing%5D%22&label=testing) |
| Report submitted | ![Reports](https://img.shields.io/github/issues-search/Sigilith/threelineage-verification?query=is%3Aissue%20is%3Aopen%20in%3Atitle%20%22%5BReplication%3A%20Report%20submitted%5D%22&label=reports) |
| Independently reproduced | ![Reproduced](https://img.shields.io/github/issues-search/Sigilith/threelineage-verification?query=is%3Aissue%20is%3Aopen%20in%3Atitle%20%22%5BReplication%3A%20Independently%20reproduced%5D%22&label=independently%20reproduced) |

To keep the counts meaningful, maintain one issue per evaluator/team and update its title only when that stage is genuinely reached. Registration is not a test result; a submitted report is not necessarily a pass. The independently reproduced count should only be used when a report documents successful reproduction of the pinned snapshot. Closed issues are not included in these live counts.

The registration record is voluntary and public. Evaluators should not post private contact details, credentials, keys, customer data, or confidential environment information. A pseudonym is acceptable.

The register measures participation and reported software replication only. It is not a download counter and does not establish hardware-backed trust, live OT/ICS capability, safety certification, regulatory approval, or general security certification.

The pinned evaluator archive and checksum sidecar are distributed from the release handoff location. Before use, evaluators must verify the checksum and follow [the external replication handoff guide](docs/EXTERNAL_REPLICATION_HANDOFF.md).
