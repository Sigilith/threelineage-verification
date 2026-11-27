"""Integrated V1.1.0 scenario: autonomy under pressure, bounded delegation and evidence."""

from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from adapters.ot.boundary import NonActuatingOTBoundaryAdapter, OTTelemetryFrame
from core.identity import DelegationChainVerifier, sign_delegation_link
from core.sigilith import GovernanceVerdict, SigilithAutonomyEngine
from core.traceguard import TraceGuardLedger
from core.transaction_authorization import SQLiteReplayStore


NOW = 1_795_000_000.0
SCOPE = "grid.setpoint.adjust"


def _frame(state: float, *, quality_good: bool = True, sis_trip: bool = False) -> OTTelemetryFrame:
    return OTTelemetryFrame(
        protocol="GENERIC-OT",
        zone_id="synthetic-zone-01",
        point_id="synthetic-setpoint-01",
        normalized_state=state,
        quality_good=quality_good,
        hardware_sis_trip=sis_trip,
    )


def test_pressure_scenario_attenuates_then_holds_and_fails_closed() -> None:
    adapter = NonActuatingOTBoundaryAdapter()

    nominal = adapter.evaluate_proposal(_frame(0.46), proposed_delta=0.02)
    assert nominal.non_actuating_only is True
    assert nominal.envelope.verdict is GovernanceVerdict.PERMIT_FULL
    assert nominal.clamped_delta == pytest.approx(0.02)

    rising = adapter.evaluate_proposal(
        _frame(0.78), proposed_delta=0.04, recent_deltas=[0.02, 0.02]
    )
    assert rising.envelope.verdict is GovernanceVerdict.PERMIT_ATTENUATED
    assert 0.0 < rising.envelope.alpha < 1.0
    assert rising.clamped_delta == pytest.approx(0.04 * rising.envelope.alpha)
    assert abs(rising.clamped_delta) < abs(rising.proposed_delta)

    hold = adapter.evaluate_proposal(
        _frame(0.80), proposed_delta=0.04, recent_deltas=[0.04] * 6
    )
    assert hold.envelope.verdict is GovernanceVerdict.HOLD_ESCALATE
    assert hold.envelope.alpha == 0.0
    assert hold.clamped_delta == 0.0
    assert hold.actuation_permitted is False

    perimeter = adapter.evaluate_proposal(_frame(0.90), proposed_delta=0.01)
    assert perimeter.envelope.verdict is GovernanceVerdict.FAIL_CLOSED
    assert perimeter.envelope.permitted_delta == 0.0
    assert perimeter.clamped_delta == 0.0

    invalid = adapter.evaluate_proposal(_frame(0.50, quality_good=False), proposed_delta=0.03)
    assert invalid.envelope.verdict is GovernanceVerdict.FAIL_CLOSED
    assert invalid.clamped_delta == 0.0
    assert invalid.actuation_permitted is False


def test_verified_delegation_cap_limits_effective_permitted_delta() -> None:
    root_private = ed25519.Ed25519PrivateKey.generate()
    orchestrator_private = ed25519.Ed25519PrivateKey.generate()
    registry = {
        "operations-root": root_private.public_key(),
        "grid-orchestrator": orchestrator_private.public_key(),
    }

    root_link = sign_delegation_link(
        private_key=root_private,
        issuer="operations-root",
        subject="grid-orchestrator",
        allowed_scopes=(SCOPE,),
        max_alpha_cap=0.75,
        issued_at=NOW - 60,
        expires_at=NOW + 3600,
    )
    agent_link = sign_delegation_link(
        private_key=orchestrator_private,
        issuer="grid-orchestrator",
        subject="setpoint-agent",
        allowed_scopes=(SCOPE,),
        max_alpha_cap=0.60,
        issued_at=NOW - 30,
        expires_at=NOW + 1800,
        prev_link_hash=root_link.link_hash(),
    )
    verifier = DelegationChainVerifier(registry, trusted_roots=("operations-root",))
    authority = verifier.verify([root_link, agent_link], required_scope=SCOPE, now=NOW)

    envelope = SigilithAutonomyEngine().evaluate(
        current_state=0.46,
        proposed_delta=0.02,
        max_alpha_cap=authority.effective_alpha_cap,
    )
    assert authority.effective_alpha_cap == 0.60
    assert envelope.verdict is GovernanceVerdict.PERMIT_ATTENUATED
    assert envelope.alpha == 0.60
    assert envelope.permitted_delta == pytest.approx(0.012)
    assert envelope.alpha <= authority.effective_alpha_cap


def test_delegation_authority_escalation_is_rejected() -> None:
    root_private = ed25519.Ed25519PrivateKey.generate()
    child_private = ed25519.Ed25519PrivateKey.generate()
    registry = {
        "operations-root": root_private.public_key(),
        "grid-orchestrator": child_private.public_key(),
    }
    root_link = sign_delegation_link(
        private_key=root_private,
        issuer="operations-root",
        subject="grid-orchestrator",
        allowed_scopes=(SCOPE,),
        max_alpha_cap=0.50,
        issued_at=NOW - 60,
        expires_at=NOW + 3600,
    )
    escalated_link = sign_delegation_link(
        private_key=child_private,
        issuer="grid-orchestrator",
        subject="setpoint-agent",
        allowed_scopes=(SCOPE,),
        max_alpha_cap=0.80,
        issued_at=NOW - 30,
        expires_at=NOW + 1800,
        prev_link_hash=root_link.link_hash(),
    )
    verifier = DelegationChainVerifier(registry, trusted_roots=("operations-root",))
    with pytest.raises(ValueError, match="authority escalation"):
        verifier.verify([root_link, escalated_link], required_scope=SCOPE, now=NOW)


def test_guardian_replay_is_rejected_and_traceguard_tampering_detected(tmp_path) -> None:
    envelope = SigilithAutonomyEngine().evaluate(
        current_state=0.78,
        proposed_delta=0.04,
        recent_deltas=[0.02, 0.02],
    )
    assert envelope.verdict is GovernanceVerdict.PERMIT_ATTENUATED

    store = SQLiteReplayStore(tmp_path / "guardian.sqlite")
    ledger_path = tmp_path / "traceguard.jsonl"
    ledger = TraceGuardLedger(ledger_path)

    first, _ = store.consume_attenuated(
        key_id="setpoint-agent",
        nonce="scenario-nonce-001",
        transaction_digest="synthetic-transaction-001",
        envelope=envelope,
        ledger=ledger,
        action_id="scenario-action-001",
        proposed_delta=0.04,
    )
    replay, _ = store.consume_attenuated(
        key_id="setpoint-agent",
        nonce="scenario-nonce-001",
        transaction_digest="synthetic-transaction-001",
        envelope=envelope,
        ledger=ledger,
        action_id="scenario-action-001-replay",
        proposed_delta=0.04,
    )
    assert first is True
    assert replay is False
    assert len(ledger.records) == 1

    reloaded = TraceGuardLedger(ledger_path)
    assert len(reloaded.records) == 1
    assert reloaded.records[0].permitted_delta == pytest.approx(envelope.permitted_delta)

    rows = [json.loads(line) for line in ledger_path.read_text(encoding="utf-8").splitlines()]
    rows[0]["permitted_delta"] = 999.0
    ledger_path.write_text(
        "".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in rows),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="TraceGuard integrity failure"):
        TraceGuardLedger(ledger_path)
