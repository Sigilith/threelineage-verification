#!/usr/bin/env python3
"""
tests/test_fix_tl_find_001.py: Regression Test Suite for TL-FIND-001 / REM-SPEC-001
Covers FIX-001 through FIX-010 verifying tamper resistance, rollback defense, and normal recovery.
"""

import os
import sqlite3
import json
import time
import threading
import pytest
from pathlib import Path

from core.transaction_authorization import SQLiteReplayStore
from core.auth_sidecar import AuthSidecarManager, get_hmac_secret

@pytest.fixture
def temp_store(tmp_path):
    db_path = tmp_path / "replay_test.sqlite"
    store = SQLiteReplayStore(db_path)
    return db_path, store

def test_fix_001_row_deletion_exploit(tmp_path):
    """FIX-001: Original row-deletion exploit (ADV-003-A2) must trigger integrity failure."""
    db_path = tmp_path / "fix001.sqlite"
    store = SQLiteReplayStore(db_path)

    # Consume a nonce
    assert store.consume("key_001", "nonce_abc", "digest_123") is True

    # Simulate attacker external row deletion via SQLite CLI / filesystem edit
    db = sqlite3.connect(db_path)
    db.execute("DELETE FROM consumed_approvals WHERE nonce = 'nonce_abc'")
    db.commit()
    db.close()

    # Fresh process load attempt must fail closed (IntegrityError)
    with pytest.raises(sqlite3.IntegrityError, match="Persistence integrity check failed"):
        SQLiteReplayStore(db_path)

def test_fix_002_row_substitution(tmp_path):
    """FIX-002: Row substitution (modifying consumed nonce value) must trigger integrity failure."""
    db_path = tmp_path / "fix002.sqlite"
    store = SQLiteReplayStore(db_path)

    assert store.consume("key_001", "nonce_original", "digest_123") is True

    # Attacker modifies nonce value in database
    db = sqlite3.connect(db_path)
    db.execute("UPDATE consumed_approvals SET nonce = 'nonce_forged' WHERE nonce = 'nonce_original'")
    db.commit()
    db.close()

    with pytest.raises(sqlite3.IntegrityError, match="Persistence integrity check failed"):
        SQLiteReplayStore(db_path)

def test_fix_003_row_insertion(tmp_path):
    """FIX-003: Unauthorized row insertion must trigger integrity failure."""
    db_path = tmp_path / "fix003.sqlite"
    store = SQLiteReplayStore(db_path)

    assert store.consume("key_001", "nonce_1", "digest_1") is True

    # Attacker inserts unconsumed/unauthorized approval row
    db = sqlite3.connect(db_path)
    db.execute(
        "INSERT INTO consumed_approvals (key_id, nonce, transaction_digest, consumed_at) VALUES (?, ?, ?, ?)",
        ("key_001", "nonce_forged_injected", "digest_fake", time.time())
    )
    db.commit()
    db.close()

    with pytest.raises(sqlite3.IntegrityError, match="Persistence integrity check failed"):
        SQLiteReplayStore(db_path)

def test_fix_004_full_state_rollback(tmp_path):
    """FIX-004: Restoring older database snapshot while sidecar is mismatched triggers integrity failure."""
    db_path = tmp_path / "fix004.sqlite"
    store = SQLiteReplayStore(db_path)

    assert store.consume("key_001", "nonce_1", "digest_1") is True

    # Backup state after nonce_1
    db_backup = db_path.read_bytes()
    sidecar_path = Path(str(db_path) + ".auth.json")
    sidecar_backup = sidecar_path.read_bytes()

    # Consume nonce_2 (updates sidecar counter and state hash)
    assert store.consume("key_001", "nonce_2", "digest_2") is True

    # Attacker rolls back database snapshot to state 1, but keeps newer sidecar (or vice versa)
    db_path.write_bytes(db_backup)

    with pytest.raises(sqlite3.IntegrityError, match="Persistence integrity check failed"):
        SQLiteReplayStore(db_path)

def test_fix_005_metadata_deletion(tmp_path):
    """FIX-005: Deleting authentication sidecar file (.auth.json) triggers fail-closed rejection."""
    db_path = tmp_path / "fix005.sqlite"
    store = SQLiteReplayStore(db_path)

    assert store.consume("key_001", "nonce_1", "digest_1") is True

    # Delete sidecar file
    sidecar_path = Path(str(db_path) + ".auth.json")
    assert sidecar_path.exists()
    sidecar_path.unlink()

    with pytest.raises(sqlite3.IntegrityError, match="Persistence integrity check failed"):
        SQLiteReplayStore(db_path)

def test_fix_006_wrong_verification_key(tmp_path, monkeypatch):
    """FIX-006: Loading store with a different secret key causes HMAC signature verification failure."""
    db_path = tmp_path / "fix006.sqlite"
    store = SQLiteReplayStore(db_path)

    assert store.consume("key_001", "nonce_1", "digest_1") is True

    # Attempt to load with a different secret key
    monkeypatch.setenv("GUARDIAN_HMAC_SECRET", "completely-wrong-secret-key-attacker-supplied")

    with pytest.raises(sqlite3.IntegrityError, match="Persistence integrity check failed"):
        SQLiteReplayStore(db_path)

def test_fix_007_normal_restart_regression(tmp_path):
    """FIX-007: Normal process restart with unchanged SQLite store succeeds and preserves replay protection (ADV-001-R4)."""
    db_path = tmp_path / "fix007.sqlite"
    store1 = SQLiteReplayStore(db_path)

    assert store1.consume("key_001", "nonce_abc", "digest_123") is True

    # Simulate fresh process boot (restart store)
    store2 = SQLiteReplayStore(db_path)

    # Replay attempt must be denied
    assert store2.consume("key_001", "nonce_abc", "digest_123") is False

def test_fix_008_atomic_commit_consistency(tmp_path):
    """FIX-008: Sidecar and database remain transactionally consistent across operations."""
    db_path = tmp_path / "fix008.sqlite"
    store = SQLiteReplayStore(db_path)

    assert store.consume("key_001", "nonce_1", "digest_1") is True
    sidecar_path = Path(str(db_path) + ".auth.json")

    assert sidecar_path.exists()
    data = json.loads(sidecar_path.read_text(encoding="utf-8"))
    assert data["monotonic_counter"] == 1

def test_fix_009_concurrency_safety(tmp_path):
    """FIX-009: Concurrent attempts to consume the same nonce result in exactly one success."""
    db_path = tmp_path / "fix009.sqlite"
    store = SQLiteReplayStore(db_path)

    results = []
    def worker():
        s = SQLiteReplayStore(db_path)
        res = s.consume("key_001", "concurrent_nonce", "digest_c")
        results.append(res)

    t1 = threading.Thread(target=worker)
    t2 = threading.Thread(target=worker)
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    # Exactly one thread must succeed (True), the other must fail (False)
    assert results.count(True) == 1
    assert results.count(False) == 1

def test_fix_010_attributable_evidence(tmp_path):
    """FIX-010: Integrity failures raise clear exception messages without leaking secret material."""
    db_path = tmp_path / "fix010.sqlite"
    store = SQLiteReplayStore(db_path)
    assert store.consume("key_001", "nonce_1", "digest_1") is True

    # Tamper with sidecar state hash
    sidecar_path = Path(str(db_path) + ".auth.json")
    data = json.loads(sidecar_path.read_text(encoding="utf-8"))
    data["state_hash"] = "deadbeef" * 8
    sidecar_path.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(sqlite3.IntegrityError) as exc_info:
        SQLiteReplayStore(db_path)

    err_msg = str(exc_info.value)
    assert "Persistence integrity check failed" in err_msg
    assert "three-lineage-auth" not in err_msg


def test_rc22_active_sidecar_deletion_fails_closed(tmp_path):
    db_path = tmp_path / "active-delete.sqlite"
    store = SQLiteReplayStore(db_path)
    assert store.consume("key", "nonce-1", "digest") is True
    Path(str(db_path) + ".auth.json").unlink()
    with pytest.raises(ValueError, match="Missing authentication sidecar"):
        store.consume("key", "nonce-2", "digest")


def test_rc22_sqlite_read_error_is_not_converted_to_empty_state(tmp_path, monkeypatch):
    db_path = tmp_path / "read-error.sqlite"
    store = SQLiteReplayStore(db_path)
    def fail_read(*args, **kwargs):
        raise sqlite3.OperationalError("simulated database read failure")
    monkeypatch.setattr(store, "_connect", fail_read)
    with pytest.raises(sqlite3.OperationalError, match="simulated database read failure"):
        store._get_all_nonces()
