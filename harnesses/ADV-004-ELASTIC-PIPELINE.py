#!/usr/bin/env python3
"""
ADV-004-ELASTIC-PIPELINE: End-to-End Elastic Autonomy & Tamper-Evident Ledger Verification.

Verifies the complete Sigilith -> Guardian -> TraceGuard execution pipeline:
- Stage 0: Initialize isolated Guardian SQLiteReplayStore and TraceGuardLedger.
- Stage 1: Execute attenuated permit (PERMIT_ATTENUATED) and confirm single-use replay rejection.
- Stage 2: Execute perimeter escalation (HOLD_ESCALATE) and confirm zero actuation permit consumption.
- Stage 3: Execute AXIOMOS hard-bound breach (FAIL_CLOSED) and confirm immediate containment.
- Stage 4: Tamper with historical alpha in TraceGuardLedger and confirm fail-closed reload rejection.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.sigilith import GovernanceVerdict, SigilithAutonomyEngine
from core.traceguard import TraceGuardLedger
from core.transaction_authorization import SQLiteReplayStore


def record_artifact(name: str, data: dict[str, object]) -> None:
    out_dir = Path.cwd() / "artifacts"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / name).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run_adv_004_elastic_pipeline() -> str:
    print("=== ADV-004-ELASTIC-PIPELINE: End-to-End Elastic Autonomy & Ledger Integrity ===")

    print("[*] Stage 0: Initialising isolated Guardian replay store and TraceGuard ledger...")
    db_path = Path.cwd() / "guardian_elastic.db"
    ledger_path = Path.cwd() / "traceguard_elastic.jsonl"

    engine = SigilithAutonomyEngine()
    store = SQLiteReplayStore(db_path)
    ledger = TraceGuardLedger(ledger_path)

    print("[*] Stage 1: Evaluating destabilizing drift inside headroom (PERMIT_ATTENUATED)...")
    env_atten = engine.evaluate(current_state=0.78, proposed_delta=0.04, recent_deltas=[0.02, 0.02])
    accepted_1, digest_1 = store.consume_attenuated(
        key_id="grid-node-01",
        nonce="nonce-elastic-001",
        transaction_digest="tx-digest-001",
        envelope=env_atten,
        ledger=ledger,
        action_id="act-001",
        proposed_delta=0.04,
    )
    replay_blocked = not store.consume_attenuated(
        key_id="grid-node-01",
        nonce="nonce-elastic-001",
        transaction_digest="tx-digest-001",
        envelope=env_atten,
    )[0]
    stage1_ok = (
        env_atten.verdict == GovernanceVerdict.PERMIT_ATTENUATED
        and 0.20 <= env_atten.alpha < 1.0
        and accepted_1 is True
        and replay_blocked is True
        and len(ledger.records) == 1
        and ledger.records[0].permit_digest == digest_1
    )
    print(f"[+] Stage 1 complete: alpha={env_atten.alpha}, replay_blocked={replay_blocked}")

    print("[*] Stage 2: Evaluating converged perimeter pressure (HOLD_ESCALATE)...")
    env_hold = engine.evaluate(current_state=0.80, proposed_delta=0.04, recent_deltas=[0.04] * 6)
    accepted_2, _ = store.consume_attenuated(
        key_id="grid-node-01",
        nonce="nonce-elastic-002",
        transaction_digest="tx-digest-002",
        envelope=env_hold,
        ledger=ledger,
        action_id="act-002",
        proposed_delta=0.04,
    )
    stage2_ok = (
        env_hold.verdict == GovernanceVerdict.HOLD_ESCALATE
        and env_hold.permitted_delta == 0.0
        and accepted_2 is False
        and len(ledger.records) == 2
    )
    print(f"[+] Stage 2 complete: verdict={env_hold.verdict.value}, permit_consumed={accepted_2}")

    print("[*] Stage 3: Evaluating AXIOMOS hard-bound breach (FAIL_CLOSED)...")
    env_fc = engine.evaluate(current_state=0.91, proposed_delta=0.02)
    accepted_3, _ = store.consume_attenuated(
        key_id="grid-node-01",
        nonce="nonce-elastic-003",
        transaction_digest="tx-digest-003",
        envelope=env_fc,
        ledger=ledger,
        action_id="act-003",
        proposed_delta=0.02,
    )
    stage3_ok = (
        env_fc.verdict == GovernanceVerdict.FAIL_CLOSED
        and env_fc.permitted_delta == 0.0
        and accepted_3 is False
        and len(ledger.records) == 3
    )
    print(f"[+] Stage 3 complete: verdict={env_fc.verdict.value}, permit_consumed={accepted_3}")

    print("[*] Stage 4: Tampering with historical alpha in TraceGuard ledger...")
    raw_ledger = ledger_path.read_text(encoding="utf-8")
    tampered_ledger = raw_ledger.replace(f'"alpha":{env_atten.alpha}', '"alpha":1.0', 1)
    ledger_path.write_text(tampered_ledger, encoding="utf-8")

    tamper_rejected = False
    tamper_error = ""
    try:
        TraceGuardLedger(ledger_path)
    except ValueError as exc:
        tamper_rejected = "TraceGuard integrity failure" in str(exc)
        tamper_error = str(exc)

    print(f"[+] Stage 4 complete: tamper_rejected={tamper_rejected}")

    all_passed = stage1_ok and stage2_ok and stage3_ok and tamper_rejected
    verdict = "PASS" if all_passed else "CONTRADICTED"
    verdict_data: dict[str, object] = {
        "test_id": "ADV-004-ELASTIC-PIPELINE",
        "invariant_tested": "TL-ELASTIC-001 (Bounded Autonomy Attenuation & Ledger Chain Integrity)",
        "verdict": verdict,
        "stage1_attenuated_and_replay_blocked": stage1_ok,
        "stage2_hold_escalate_zero_actuation": stage2_ok,
        "stage3_fail_closed_hard_bound": stage3_ok,
        "stage4_ledger_tamper_rejected": tamper_rejected,
        "tamper_error": tamper_error,
    }
    record_artifact("verdict.json", verdict_data)
    print(f"=== ADV-004-ELASTIC-PIPELINE COMPLETE. VERDICT: {verdict} ===")
    return verdict


if __name__ == "__main__":
    final_verdict = run_adv_004_elastic_pipeline()
    sys.exit(0 if final_verdict == "PASS" else 1)
