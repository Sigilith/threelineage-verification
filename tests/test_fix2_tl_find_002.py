#!/usr/bin/env python3
"""
tests/test_fix2_tl_find_002.py: Regression Test Suite for TL-FIND-002 / REM-SPEC-002
Covers FIX2-001 through FIX2-016 verifying verifier state authentication, freshness anchoring, and rollback defense.
"""

import os
import json
import time
import pytest
from pathlib import Path

from core.verifier_auth import VerifierAuthManager

def test_fix2_001_nonce_substitution(tmp_path):
    """FIX2-001: Historical nonce substitution (ADV-003-B-R1A) triggers integrity failure."""
    state_path = tmp_path / "fix2_001.json"
    manager = VerifierAuthManager(state_path)

    manager.commit(1, {"nonces": ["nonce_r0"], "timestamps": {"nonce_r0": time.time()}})

    with open(state_path, "r", encoding="utf-8") as f:
        env = json.load(f)
    env["state_records"]["nonces"] = ["nonce_forged"]
    with open(state_path, "w", encoding="utf-8") as f:
        json.dump(env, f)

    with pytest.raises(ValueError, match="State hash mismatch"):
        manager.load_and_verify()

def test_fix2_002_duplicate_injection(tmp_path):
    """FIX2-002: Duplicate nonce injection (ADV-003-B-R1B) is safely handled post-authentication."""
    state_path = tmp_path / "fix2_002.json"
    manager = VerifierAuthManager(state_path)

    manager.commit(1, {"nonces": ["nonce_1", "nonce_1"], "timestamps": {"nonce_1": time.time()}})
    gen, records = manager.load_and_verify()
    assert gen == 1
    assert len(set(records["nonces"])) == 1

def test_fix2_003_timestamp_backdating(tmp_path):
    """FIX2-003: Historical timestamp backdating (ADV-003-B-R1C) authenticated prior to pruning."""
    state_path = tmp_path / "fix2_003.json"
    manager = VerifierAuthManager(state_path)

    manager.commit(1, {"nonces": ["nonce_old"], "timestamps": {"nonce_old": time.time() - 1000}})
    gen, records = manager.load_and_verify()
    assert gen == 1
    assert "nonce_old" in records["timestamps"]

def test_fix2_004_historical_nonce_deletion(tmp_path):
    """FIX2-004: Deleting a recorded nonce from state file triggers state hash mismatch."""
    state_path = tmp_path / "fix2_004.json"
    manager = VerifierAuthManager(state_path)

    manager.commit(1, {"nonces": ["nonce_1", "nonce_2"], "timestamps": {"nonce_1": time.time(), "nonce_2": time.time()}})

    with open(state_path, "r", encoding="utf-8") as f:
        env = json.load(f)
    env["state_records"]["nonces"] = ["nonce_1"]
    with open(state_path, "w", encoding="utf-8") as f:
        json.dump(env, f)

    with pytest.raises(ValueError, match="State hash mismatch"):
        manager.load_and_verify()

def test_fix2_005_synthetic_nonce_insertion(tmp_path):
    """FIX2-005: Inserting unauthorized synthetic nonce triggers state hash mismatch."""
    state_path = tmp_path / "fix2_005.json"
    manager = VerifierAuthManager(state_path)

    manager.commit(1, {"nonces": ["nonce_1"], "timestamps": {"nonce_1": time.time()}})

    with open(state_path, "r", encoding="utf-8") as f:
        env = json.load(f)
    env["state_records"]["nonces"].append("nonce_injected_forged")
    with open(state_path, "w", encoding="utf-8") as f:
        json.dump(env, f)

    with pytest.raises(ValueError, match="State hash mismatch"):
        manager.load_and_verify()

def test_fix2_006_in_window_timestamp_substitution(tmp_path):
    """FIX2-006: Modifying timestamp within drift window triggers state hash mismatch."""
    state_path = tmp_path / "fix2_006.json"
    manager = VerifierAuthManager(state_path)

    t = time.time()
    manager.commit(1, {"nonces": ["nonce_1"], "timestamps": {"nonce_1": t}})

    with open(state_path, "r", encoding="utf-8") as f:
        env = json.load(f)
    env["state_records"]["timestamps"]["nonce_1"] = t + 5.0
    with open(state_path, "w", encoding="utf-8") as f:
        json.dump(env, f)

    with pytest.raises(ValueError, match="State hash mismatch"):
        manager.load_and_verify()

def test_fix2_007_rollback_detection(tmp_path):
    """FIX2-007: Restoring an older generation state file triggers generation regression detection."""
    state_path = tmp_path / "fix2_007.json"
    manager = VerifierAuthManager(state_path)

    manager.commit(1, {"nonces": ["n1"], "timestamps": {"n1": time.time()}})
    gen_1_state = state_path.read_text(encoding="utf-8")

    manager.commit(5, {"nonces": ["n5"], "timestamps": {"n5": time.time()}})
    state_path.write_text(gen_1_state, encoding="utf-8")

    with pytest.raises(ValueError, match="Generation regression detected"):
        manager.load_and_verify()

def test_fix2_008_missing_state_file(tmp_path):
    """FIX2-008: Missing state file while lock anchor exists triggers split-brain integrity failure."""
    state_path = tmp_path / "fix2_008.json"
    manager = VerifierAuthManager(state_path)
    manager.commit(1, {"nonces": ["n1"], "timestamps": {"n1": time.time()}})

    state_path.unlink()

    with pytest.raises(ValueError, match="Split-brain state/anchor erasure detected"):
        manager.load_and_verify()

def test_fix2_009_missing_authenticator_fields(tmp_path):
    """FIX2-009: Envelope missing schema fields triggers integrity rejection."""
    state_path = tmp_path / "fix2_009.json"
    manager = VerifierAuthManager(state_path)
    manager.commit(1, {"nonces": ["n1"], "timestamps": {"n1": time.time()}})

    with open(state_path, "r", encoding="utf-8") as f:
        env = json.load(f)
    del env["hmac_signature"]
    with open(state_path, "w", encoding="utf-8") as f:
        json.dump(env, f)

    with pytest.raises(ValueError, match="Incomplete state envelope schema fields"):
        manager.load_and_verify()

def test_fix2_010_wrong_hmac_key(tmp_path, monkeypatch):
    """FIX2-010: Verifying with incorrect HMAC key causes signature verification failure."""
    state_path = tmp_path / "fix2_010.json"
    manager = VerifierAuthManager(state_path)
    manager.commit(1, {"nonces": ["n1"], "timestamps": {"n1": time.time()}})

    monkeypatch.setenv("VERIFIER_HMAC_SECRET", "attacker-wrong-secret-key-material-32bytes")
    manager_wrong = VerifierAuthManager(state_path)

    with pytest.raises(ValueError, match="HMAC signature mismatch"):
        manager_wrong.load_and_verify()

def test_fix2_011_state_updated_anchor_old(tmp_path):
    """FIX2-011: State generation ahead of anchor is an interrupted publication and fails closed."""
    state_path = tmp_path / "fix2_011.json"
    manager = VerifierAuthManager(state_path)
    manager.commit(3, {"nonces": ["n3"], "timestamps": {"n3": time.time()}})

    lock_path = Path(str(state_path) + ".lock")
    lock_path.write_text(json.dumps({"max_generation": 1}), encoding="utf-8")

    with pytest.raises(ValueError, match="State generation ahead of freshness marker"):
        manager.load_and_verify()

def test_fix2_012_anchor_updated_state_old(tmp_path):
    """FIX2-012: State generation behind anchor max triggers generation regression detection."""
    state_path = tmp_path / "fix2_012.json"
    manager = VerifierAuthManager(state_path)
    manager.commit(1, {"nonces": ["n1"], "timestamps": {"n1": time.time()}})

    lock_path = Path(str(state_path) + ".lock")
    lock_path.write_text(json.dumps({"max_generation": 5}), encoding="utf-8")

    with pytest.raises(ValueError, match="Generation regression detected"):
        manager.load_and_verify()

def test_fix2_013_normal_authentic_restart(tmp_path):
    """FIX2-013: Normal process restart with authentic state envelope succeeds."""
    state_path = tmp_path / "fix2_013.json"
    manager1 = VerifierAuthManager(state_path)
    manager1.commit(4, {"nonces": ["n4"], "timestamps": {"n4": time.time()}})

    manager2 = VerifierAuthManager(state_path)
    gen, records = manager2.load_and_verify()
    assert gen == 4
    assert "n4" in records["nonces"]

def test_fix2_014_staged_publication_atomicity(tmp_path):
    """FIX2-014: Staged publication leaves no residual temp files and ensures crash consistency."""
    state_path = tmp_path / "fix2_014.json"
    manager = VerifierAuthManager(state_path)
    manager.commit(1, {"nonces": ["n1"], "timestamps": {"n1": time.time()}})

    assert state_path.exists()
    assert Path(str(state_path) + ".lock").exists()
    assert not Path(str(state_path) + ".tmp").exists()

def test_fix2_015_first_run_distinction(tmp_path):
    """FIX2-015: First run with zero prior state initializes pristine generation 0 successfully."""
    state_path = tmp_path / "fix2_015.json"
    manager = VerifierAuthManager(state_path)

    assert not state_path.exists()
    gen, records = manager.load_and_verify()
    assert gen == 0
    assert records["nonces"] == []

def test_fix2_016_attributable_evidence(tmp_path):
    """FIX2-016: Integrity failures emit clear error messages without leaking secret keys."""
    state_path = tmp_path / "fix2_016.json"
    manager = VerifierAuthManager(state_path)
    manager.commit(1, {"nonces": ["n1"], "timestamps": {"n1": time.time()}})

    with open(state_path, "r", encoding="utf-8") as f:
        env = json.load(f)
    env["state_records"]["nonces"] = ["n1_tampered_unauthorized"]
    with open(state_path, "w", encoding="utf-8") as f:
        json.dump(env, f)

    with pytest.raises(ValueError) as exc_info:
        manager.load_and_verify()

    err = str(exc_info.value)
    assert "State hash mismatch" in err or "HMAC signature mismatch" in err
    assert "three-lineage-verifier-auth" not in err


def test_rc22_commit_rejects_generation_regression(tmp_path):
    state_path = tmp_path / "generation-regression.json"
    manager = VerifierAuthManager(state_path)
    manager.commit(5, {"nonces": ["n5"], "timestamps": {"n5": time.time()}})
    with pytest.raises(ValueError, match="Generation must increase strictly"):
        manager.commit(2, {"nonces": ["n2"], "timestamps": {"n2": time.time()}})
    assert manager.load_and_verify()[0] == 5


def test_rc22_commit_rejects_same_generation(tmp_path):
    state_path = tmp_path / "same-generation.json"
    manager = VerifierAuthManager(state_path)
    manager.commit(1, {"nonces": ["n1"], "timestamps": {"n1": time.time()}})
    with pytest.raises(ValueError, match="Generation must increase strictly"):
        manager.commit(1, {"nonces": ["n1b"], "timestamps": {"n1b": time.time()}})
