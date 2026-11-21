"""Tests proving requester identity, delegation chain continuity, and monotonic authority bounds."""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import ed25519
import pytest

from core.identity import DelegationChainVerifier, sign_delegation_link
from core.sigilith import GovernanceVerdict, SigilithAutonomyEngine
from core.traceguard import TraceGuardLedger
from core.transaction_authorization import SQLiteReplayStore


def _build_fixture_keys():
    root_priv = ed25519.Ed25519PrivateKey.generate()
    orch_priv = ed25519.Ed25519PrivateKey.generate()
    agent_priv = ed25519.Ed25519PrivateKey.generate()
    rogue_priv = ed25519.Ed25519PrivateKey.generate()
    registry = {
        "ops-director": root_priv.public_key(),
        "grid-orchestrator": orch_priv.public_key(),
        "actuation-agent-07": agent_priv.public_key(),
        "rogue-principal": rogue_priv.public_key(),
    }
    return root_priv, orch_priv, agent_priv, rogue_priv, registry


def test_valid_multi_hop_delegation_bounds_alpha_and_records_attribution(tmp_path) -> None:
    root_priv, orch_priv, _, _, registry = _build_fixture_keys()
    now = 1_795_000_000.0

    # Hop 1: ops-director delegates to grid-orchestrator with max_alpha_cap=0.75
    hop1 = sign_delegation_link(
        private_key=root_priv,
        issuer="ops-director",
        subject="grid-orchestrator",
        allowed_scopes=("grid.setpoint.adjust", "grid.telemetry.read"),
        max_alpha_cap=0.75,
        issued_at=now - 60,
        expires_at=now + 3600,
    )
    # Hop 2: grid-orchestrator narrows scope and caps alpha at 0.60 for actuation-agent-07
    hop2 = sign_delegation_link(
        private_key=orch_priv,
        issuer="grid-orchestrator",
        subject="actuation-agent-07",
        allowed_scopes=("grid.setpoint.adjust",),
        max_alpha_cap=0.60,
        issued_at=now - 30,
        expires_at=now + 1800,
        prev_link_hash=hop1.link_hash(),
    )

    verifier = DelegationChainVerifier(registry, trusted_roots=("ops-director",))
    authority = verifier.verify([hop1, hop2], required_scope="grid.setpoint.adjust", now=now)

    assert authority.root_principal == "ops-director"
    assert authority.requester_id == "actuation-agent-07"
    assert authority.delegation_path == ("ops-director", "grid-orchestrator", "actuation-agent-07")
    assert authority.delegation_depth == 2
    assert authority.effective_alpha_cap == 0.60

    # Sigilith evaluates a nominal action that would otherwise get alpha=1.0 -> capped to 0.60
    engine = SigilithAutonomyEngine()
    env = engine.evaluate(
        current_state=0.46,
        proposed_delta=0.02,
        max_alpha_cap=authority.effective_alpha_cap,
    )
    assert env.verdict == GovernanceVerdict.PERMIT_ATTENUATED
    assert env.alpha == 0.60
    assert env.permitted_delta == pytest.approx(0.012)

    # Guardian binds permit to delegation chain and records non-repudiable TraceGuard entry
    store = SQLiteReplayStore(tmp_path / "guardian.db")
    ledger = TraceGuardLedger(tmp_path / "traceguard.jsonl")
    ok, _ = store.consume_attenuated(
        key_id="grid-orchestrator",
        nonce="n-delegated-001",
        transaction_digest="tx-setpoint-99",
        envelope=env,
        ledger=ledger,
        action_id="act-delegated-001",
        proposed_delta=0.02,
        authority=authority,
    )
    assert ok is True
    rec = ledger.records[0]
    assert rec.root_principal == "ops-director"
    assert rec.requester_id == "actuation-agent-07"
    assert rec.delegation_depth == 2
    assert rec.chain_digest == authority.chain_digest


def test_delegation_chain_rejects_escalation_and_tampering(tmp_path) -> None:
    root_priv, orch_priv, _, rogue_priv, registry = _build_fixture_keys()
    now = 1_795_000_000.0
    verifier = DelegationChainVerifier(registry, trusted_roots=("ops-director",))

    hop1 = sign_delegation_link(
        private_key=root_priv,
        issuer="ops-director",
        subject="grid-orchestrator",
        allowed_scopes=("grid.setpoint.adjust",),
        max_alpha_cap=0.50,
        issued_at=now - 60,
        expires_at=now + 3600,
    )

    # 1. Alpha cap escalation rejected (0.80 > parent 0.50)
    bad_alpha_hop = sign_delegation_link(
        private_key=orch_priv,
        issuer="grid-orchestrator",
        subject="actuation-agent-07",
        allowed_scopes=("grid.setpoint.adjust",),
        max_alpha_cap=0.80,
        issued_at=now - 30,
        expires_at=now + 1800,
        prev_link_hash=hop1.link_hash(),
    )
    with pytest.raises(ValueError, match="authority escalation"):
        verifier.verify([hop1, bad_alpha_hop], required_scope="grid.setpoint.adjust", now=now)

    # 2. Scope escalation rejected
    bad_scope_hop = sign_delegation_link(
        private_key=orch_priv,
        issuer="grid-orchestrator",
        subject="actuation-agent-07",
        allowed_scopes=("grid.setpoint.adjust", "grid.breaker.trip"),
        max_alpha_cap=0.40,
        issued_at=now - 30,
        expires_at=now + 1800,
        prev_link_hash=hop1.link_hash(),
    )
    with pytest.raises(ValueError, match="scope escalation"):
        verifier.verify([hop1, bad_scope_hop], required_scope="grid.setpoint.adjust", now=now)

    # 3. Untrusted root rejected
    rogue_hop = sign_delegation_link(
        private_key=rogue_priv,
        issuer="rogue-principal",
        subject="actuation-agent-07",
        allowed_scopes=("grid.setpoint.adjust",),
        max_alpha_cap=0.40,
        issued_at=now - 30,
        expires_at=now + 1800,
    )
    with pytest.raises(ValueError, match="untrusted root principal"):
        verifier.verify([rogue_hop], required_scope="grid.setpoint.adjust", now=now)
