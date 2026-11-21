"""Tests for Sigilith alpha=f(H,D,Delta), Guardian attenuated permits, and TraceGuard ledger."""

from __future__ import annotations

import pytest

from core.sigilith import GovernanceVerdict, SigilithAutonomyEngine
from core.traceguard import TraceGuardLedger
from core.transaction_authorization import SQLiteReplayStore


def test_sigilith_four_cases_headroom_and_direction() -> None:
    engine = SigilithAutonomyEngine()

    # Case A: Corrective action moving toward nominal restores safety margin -> alpha = 1.0
    env_a = engine.evaluate(current_state=0.78, proposed_delta=-0.08, recent_deltas=[0.04, 0.04, 0.04])
    assert env_a.verdict == GovernanceVerdict.PERMIT_FULL
    assert env_a.alpha == 1.0
    assert env_a.action_direction == "STABILIZING"
    assert env_a.permitted_delta == pytest.approx(-0.08)

    # Case B: Mildly increasing pressure -> smooth attenuation
    env_b = engine.evaluate(current_state=0.78, proposed_delta=0.04, recent_deltas=[0.02, 0.02])
    assert env_b.verdict == GovernanceVerdict.PERMIT_ATTENUATED
    assert 0.40 <= env_b.alpha < 1.0
    assert env_b.action_direction == "DESTABILIZING"

    # Case C: Aggressive boundary approach near perimeter -> strongly constrained alpha
    env_c = engine.evaluate(current_state=0.84, proposed_delta=0.04, recent_deltas=[0.02, 0.02])
    assert env_c.verdict == GovernanceVerdict.PERMIT_ATTENUATED
    assert 0.20 <= env_c.alpha <= 0.35

    # Case D: Converged danger signal -> HOLD_ESCALATE with zero permitted delta
    env_d = engine.evaluate(current_state=0.80, proposed_delta=0.04, recent_deltas=[0.04] * 6)
    assert env_d.verdict == GovernanceVerdict.HOLD_ESCALATE
    assert env_d.alpha == 0.0
    assert env_d.permitted_delta == 0.0

    # AXIOMOS hard perimeter breach -> FAIL_CLOSED
    env_fc = engine.evaluate(current_state=0.90, proposed_delta=0.01)
    assert env_fc.verdict == GovernanceVerdict.FAIL_CLOSED
    assert env_fc.alpha == 0.0


def test_guardian_attenuated_permit_and_traceguard_chain(tmp_path) -> None:
    engine = SigilithAutonomyEngine()
    store = SQLiteReplayStore(tmp_path / "guardian.db")
    ledger = TraceGuardLedger(tmp_path / "traceguard.jsonl")

    # 1. Attenuated action succeeds once, records telemetry, and rejects replay
    env = engine.evaluate(current_state=0.78, proposed_delta=0.04, recent_deltas=[0.02, 0.02])
    ok, digest = store.consume_attenuated(
        key_id="node-01",
        nonce="n-001",
        transaction_digest="tx-abc",
        envelope=env,
        ledger=ledger,
        action_id="act-001",
        proposed_delta=0.04,
    )
    assert ok is True
    assert len(ledger.records) == 1
    rec = ledger.records[0]
    assert rec.permit_digest == digest
    assert rec.alpha == env.alpha
    assert rec.headroom_pressure == env.headroom_pressure
    assert rec.action_direction == "DESTABILIZING"

    # Replay of same nonce fails closed
    replay_ok, _ = store.consume_attenuated(
        key_id="node-01",
        nonce="n-001",
        transaction_digest="tx-abc",
        envelope=env,
    )
    assert replay_ok is False

    # 2. Escalated action does not consume permit, still logs forensic record
    esc_env = engine.evaluate(current_state=0.88, proposed_delta=0.02)
    esc_ok, _ = store.consume_attenuated(
        key_id="node-01",
        nonce="n-002",
        transaction_digest="tx-def",
        envelope=esc_env,
        ledger=ledger,
        action_id="act-002",
        proposed_delta=0.02,
    )
    assert esc_ok is False
    assert len(ledger.records) == 2
    assert ledger.records[1].verdict == "HOLD_ESCALATE"

    # 3. Reloading ledger verifies chain; tampering fails closed
    reloaded = TraceGuardLedger(tmp_path / "traceguard.jsonl")
    assert len(reloaded.records) == 2

    tampered = (tmp_path / "traceguard.jsonl").read_text(encoding="utf-8").replace('"alpha":0.55', '"alpha":1.0')
    if tampered == (tmp_path / "traceguard.jsonl").read_text(encoding="utf-8"):
        tampered = (tmp_path / "traceguard.jsonl").read_text(encoding="utf-8").replace("DESTABILIZING", "STABILIZING")
    (tmp_path / "traceguard.jsonl").write_text(tampered, encoding="utf-8")

    with pytest.raises(ValueError, match="TraceGuard integrity failure"):
        TraceGuardLedger(tmp_path / "traceguard.jsonl")
