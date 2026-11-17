import shutil
import sqlite3
import time

import pytest

from core.auth_sidecar import AuthSidecarManager
from core.transaction_authorization import SQLiteReplayStore
from core.verifier_auth import VerifierAuthManager


def test_sqlite_commit_before_sidecar_failure_is_detected(tmp_path, monkeypatch):
    db_path = tmp_path / "replay.sqlite"
    store = SQLiteReplayStore(db_path)

    def fail_sidecar_commit(self, new_counter, current_nonces):
        raise OSError("simulated interruption before sidecar replacement")

    monkeypatch.setattr(AuthSidecarManager, "commit", fail_sidecar_commit)
    with pytest.raises(OSError, match="simulated interruption"):
        store.consume("key-a", "nonce-a", "digest-a")

    # SQLite committed first. The old sidecar is now inconsistent and the next
    # access must reject the store rather than auto-heal or silently reset it.
    with sqlite3.connect(db_path) as db:
        assert db.execute("SELECT COUNT(*) FROM consumed_approvals").fetchone()[0] == 1

    with pytest.raises(sqlite3.IntegrityError, match="Persistence integrity check failed"):
        SQLiteReplayStore(db_path)


def test_paired_local_rollback_is_documented_out_of_scope(tmp_path):
    state_path = tmp_path / "verifier.state"
    manager = VerifierAuthManager(state_path)
    manager.commit(1, {"nonces": ["n1"], "timestamps": {"n1": time.time()}})

    state_backup = tmp_path / "state.g1"
    anchor_backup = tmp_path / "anchor.g1"
    shutil.copy2(state_path, state_backup)
    shutil.copy2(str(state_path) + ".lock", anchor_backup)

    manager.commit(2, {"nonces": ["n2"], "timestamps": {"n2": time.time()}})
    shutil.copy2(state_backup, state_path)
    shutil.copy2(anchor_backup, str(state_path) + ".lock")

    # This is an explicit limitation demonstration: both local files restored
    # together form an older valid pair. No independent anchor is claimed.
    generation, records = manager.load_and_verify()
    assert generation == 1
    assert records["nonces"] == ["n1"]
