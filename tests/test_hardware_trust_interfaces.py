"""Tests for hardware-anchored trust abstractions (TPM counter, HSM root, witness log)."""

from __future__ import annotations

import pytest

from core.hardware_trust import (
    InMemoryMonotonicCounter,
    InMemoryTransparencyLog,
    ReferenceHSMRoot,
)
from core.sigilith import SigilithAutonomyEngine
from core.traceguard import TraceGuardLedger


def test_monotonic_counter_advances_and_rejects_non_positive_step() -> None:
    counter = InMemoryMonotonicCounter(initial_value=10)
    a1 = counter.advance("tpm-nv-01")
    a2 = counter.advance("tpm-nv-01", min_step=3)

    assert a1.value == 11
    assert a2.value == 14
    assert counter.current_value("tpm-nv-01") == 14
    assert a1.attestation_digest != a2.attestation_digest

    with pytest.raises(ValueError):
        counter.advance("tpm-nv-01", min_step=0)


def test_hsm_root_signs_and_verifies_digest() -> None:
    hsm = ReferenceHSMRoot("hsm-cni-root-01", b"test-secret-material-32-bytes-ok")
    digest = "a" * 64
    sig = hsm.sign_digest(digest)

    assert hsm.verify_digest_signature(digest, sig) is True
    assert hsm.verify_digest_signature(digest, "0" * 64) is False


def test_transparency_log_checkpoint_links_traceguard_head(tmp_path) -> None:
    ledger = TraceGuardLedger(tmp_path / "traceguard.jsonl")
    engine = SigilithAutonomyEngine()
    env = engine.evaluate(current_state=0.46, proposed_delta=0.01)
    ledger.append(
        action_id="act-witness-01",
        permit_digest="b" * 64,
        proposed_delta=0.01,
        envelope=env,
    )

    log = InMemoryTransparencyLog("cni-witness-01")
    cp = log.publish_checkpoint(ledger_head_hash=ledger.head_hash, chain_digest="c" * 64)

    assert cp.checkpoint_seq == 1
    assert cp.ledger_head_hash == ledger.head_hash
    assert log.verify_checkpoint(cp) is True
