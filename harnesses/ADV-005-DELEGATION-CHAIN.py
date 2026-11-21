#!/usr/bin/env python3
"""
ADV-005-DELEGATION-CHAIN: End-to-End Delegation Attribution & Escalation Rejection Verification.

Proves who requested the action, who delegated authority, and what bounded chain existed:
- Stage 0: Generate Ed25519 keys for root principal, orchestrator, leaf agent, and rogue actor.
- Stage 1: Verify multi-hop delegation chain with monotonic alpha cap (1.0 -> 0.75 -> 0.55)
           and execute bound permit through Sigilith -> Guardian -> TraceGuard.
- Stage 2: Confirm TraceGuard ledger persists root_principal, requester_id, delegation_depth,
           and chain_digest, and rejects post-hoc requester_id forgery on reload.
- Stage 3: Confirm confused-deputy alpha escalation and scope escalation fail closed.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys
import time

from cryptography.hazmat.primitives.asymmetric import ed25519

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.identity import DelegationChainVerifier, sign_delegation_link
from core.sigilith import GovernanceVerdict, SigilithAutonomyEngine
from core.traceguard import TraceGuardLedger
from core.transaction_authorization import SQLiteReplayStore


def record_artifact(name: str, data: dict[str, object]) -> None:
    out_dir = Path.cwd() / "artifacts"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / name).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run_adv_005_delegation_chain() -> str:
    print("=== ADV-005-DELEGATION-CHAIN: Principal Attribution & Authority Chain Verification ===")

    print("[*] Stage 0: Initialising Ed25519 principal keys and isolated runtime stores...")
    root_priv = ed25519.Ed25519PrivateKey.generate()
    orch_priv = ed25519.Ed25519PrivateKey.generate()
    agent_priv = ed25519.Ed25519PrivateKey.generate()
    rogue_priv = ed25519.Ed25519PrivateKey.generate()

    registry = {
        "cni-ops-root": root_priv.public_key(),
        "substation-orchestrator": orch_priv.public_key(),
        "field-agent-04": agent_priv.public_key(),
        "rogue-actor": rogue_priv.public_key(),
    }
    verifier = DelegationChainVerifier(registry, trusted_roots=("cni-ops-root",))
    engine = SigilithAutonomyEngine()
    store = SQLiteReplayStore(Path.cwd() / "guardian_delegation.db")
    ledger_path = Path.cwd() / "traceguard_delegation.jsonl"
    ledger = TraceGuardLedger(ledger_path)

    print("[*] Stage 1: Verifying multi-hop delegation chain and executing bounded permit...")
    now = time.time()
    hop1 = sign_delegation_link(
        private_key=root_priv,
        issuer="cni-ops-root",
        subject="substation-orchestrator",
        allowed_scopes=("setpoint.trim", "telemetry.read"),
        max_alpha_cap=0.75,
        issued_at=now - 30,
        expires_at=now + 600,
    )
    hop2 = sign_delegation_link(
        private_key=orch_priv,
        issuer="substation-orchestrator",
        subject="field-agent-04",
        allowed_scopes=("setpoint.trim",),
        max_alpha_cap=0.55,
        issued_at=now - 15,
        expires_at=now + 300,
        prev_link_hash=hop1.link_hash(),
    )
    authority = verifier.verify([hop1, hop2], required_scope="setpoint.trim", now=now)
    env = engine.evaluate(current_state=0.46, proposed_delta=0.02, max_alpha_cap=authority.effective_alpha_cap)
    accepted, digest = store.consume_attenuated(
        key_id="substation-orchestrator",
        nonce="nonce-del-001",
        transaction_digest="tx-del-001",
        envelope=env,
        ledger=ledger,
        action_id="act-del-001",
        proposed_delta=0.02,
        authority=authority,
    )
    rec = ledger.records[0]
    stage1_ok = (
        accepted is True
        and env.verdict == GovernanceVerdict.PERMIT_ATTENUATED
        and env.alpha == 0.55
        and rec.root_principal == "cni-ops-root"
        and rec.requester_id == "field-agent-04"
        and rec.delegation_depth == 2
        and rec.chain_digest == authority.chain_digest
        and rec.permit_digest == digest
    )
    print(
        f"[+] Stage 1 complete: root={rec.root_principal}, requester={rec.requester_id}, "
        f"depth={rec.delegation_depth}, alpha={rec.alpha}"
    )

    print("[*] Stage 2: Tampering with requester_id in TraceGuard ledger to test non-repudiation...")
    tampered_path = Path.cwd() / "traceguard_delegation_tampered.jsonl"
    tampered_text = ledger_path.read_text(encoding="utf-8").replace("field-agent-04", "field-agent-99")
    tampered_path.write_text(tampered_text, encoding="utf-8")
    tamper_rejected = False
    try:
        TraceGuardLedger(tampered_path)
    except ValueError as exc:
        tamper_rejected = "TraceGuard integrity failure" in str(exc)
    print(f"[+] Stage 2 complete: requester_forgery_rejected={tamper_rejected}")

    print("[*] Stage 3: Probing confused-deputy alpha escalation and untrusted root injection...")
    escalated_hop = sign_delegation_link(
        private_key=orch_priv,
        issuer="substation-orchestrator",
        subject="field-agent-04",
        allowed_scopes=("setpoint.trim",),
        max_alpha_cap=0.95,
        issued_at=now - 10,
        expires_at=now + 300,
        prev_link_hash=hop1.link_hash(),
    )
    escalation_blocked = False
    try:
        verifier.verify([hop1, escalated_hop], required_scope="setpoint.trim", now=now)
    except ValueError:
        escalation_blocked = True

    rogue_hop = sign_delegation_link(
        private_key=rogue_priv,
        issuer="rogue-actor",
        subject="field-agent-04",
        allowed_scopes=("setpoint.trim",),
        max_alpha_cap=0.50,
        issued_at=now - 10,
        expires_at=now + 300,
    )
    rogue_blocked = False
    try:
        verifier.verify([rogue_hop], required_scope="setpoint.trim", now=now)
    except ValueError:
        rogue_blocked = True

    stage3_ok = escalation_blocked and rogue_blocked
    print(f"[+] Stage 3 complete: escalation_blocked={escalation_blocked}, rogue_blocked={rogue_blocked}")

    all_passed = stage1_ok and tamper_rejected and stage3_ok
    verdict = "PASS" if all_passed else "CONTRADICTED"
    record_artifact(
        "verdict.json",
        {
            "test_id": "ADV-005-DELEGATION-CHAIN",
            "invariant_tested": "TL-ID-001 (Cryptographic Delegation Attribution & Monotonic Authority Bounds)",
            "verdict": verdict,
            "stage1_attribution_verified": stage1_ok,
            "stage2_requester_forgery_rejected": tamper_rejected,
            "stage3_escalation_and_rogue_blocked": stage3_ok,
        },
    )
    print(f"=== ADV-005-DELEGATION-CHAIN COMPLETE. VERDICT: {verdict} ===")
    return verdict


if __name__ == "__main__":
    final_verdict = run_adv_005_delegation_chain()
    sys.exit(0 if final_verdict == "PASS" else 1)
