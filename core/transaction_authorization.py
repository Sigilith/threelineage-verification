#!/usr/bin/env python3
"""
core/transaction_authorization.py: Transaction authorization and durable replay store with AuthSidecar integration.
"""

import sqlite3
import time
import contextlib
import os
import fcntl
from pathlib import Path
from typing import Any
from core.auth_sidecar import AuthSidecarManager

class SQLiteReplayStore:
    """Durable, concurrency-safe nonce store with cryptographic sidecar authentication (TL-FIND-001 mitigation)."""

    def __init__(self, path: str | Path):
        self.path = str(path)
        self.sidecar = AuthSidecarManager(self.path)
        self.lock_path = self.path + ".writer.lock"

        # Serialize startup verification with all consumers so no process can
        # observe the deliberate SQLite-commit/sidecar-replace interval.
        with self._exclusive_lock():
            db_exists = Path(self.path).exists()
            db = self._connect()
            try:
                db.execute("""
                    CREATE TABLE IF NOT EXISTS consumed_approvals (
                        key_id TEXT NOT NULL,
                        nonce TEXT NOT NULL,
                        transaction_digest TEXT NOT NULL,
                        consumed_at REAL NOT NULL,
                        PRIMARY KEY (key_id, nonce)
                    )
                """)
            finally:
                db.close()

            # If database already existed, verify sidecar integrity on startup (Fail-Closed)
            if db_exists:
                try:
                    current_nonces = self._get_all_nonces()
                    self.sidecar.load_and_verify(current_nonces)
                except Exception as e:
                    raise sqlite3.IntegrityError(f"Persistence integrity check failed: {e}") from e
            else:
                # Initialize fresh sidecar with counter 0
                self.sidecar.commit(0, [])

    @contextlib.contextmanager
    def _exclusive_lock(self):
        parent = os.path.dirname(os.path.abspath(self.lock_path))
        os.makedirs(parent, exist_ok=True)
        with open(self.lock_path, "a+", encoding="utf-8") as lock_file:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)

    def _connect(self):
        db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        db.execute("PRAGMA busy_timeout=10000")
        return db

    def _get_all_nonces(self, db_conn=None) -> list:
        """Read all consumed nonces; database errors are never converted to empty state."""
        if db_conn is not None:
            cursor = db_conn.execute(
                "SELECT key_id, nonce FROM consumed_approvals ORDER BY key_id, nonce"
            )
            return [f"{row[0]}:{row[1]}" for row in cursor.fetchall()]
        with contextlib.closing(self._connect()) as db:
            cursor = db.execute(
                "SELECT key_id, nonce FROM consumed_approvals ORDER BY key_id, nonce"
            )
            return [f"{row[0]}:{row[1]}" for row in cursor.fetchall()]

    def consume(self, key_id: str, nonce: str, digest: str) -> bool:
        """Consume a nonce. Duplicate nonce returns False; integrity/I/O errors raise."""
        with self._exclusive_lock():
            return self._consume_locked(key_id, nonce, digest)

    def _consume_locked(self, key_id: str, nonce: str, digest: str) -> bool:
        with contextlib.closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                # A missing sidecar is always an integrity failure, including during an
                # active session. Never silently reinitialize an existing database.
                current_nonces = self._get_all_nonces(db)
                counter = self.sidecar.load_and_verify(current_nonces)

                db.execute(
                    "INSERT INTO consumed_approvals (key_id, nonce, transaction_digest, consumed_at) VALUES (?, ?, ?, ?)",
                    (key_id, nonce, digest, time.time()),
                )
                updated_nonces = self._get_all_nonces(db)
                # Commit the SQLite authority first. The sidecar is a separate file,
                # so a crash before its atomic replacement leaves a detectable
                # mismatch and the next access fails closed for admin reconciliation.
                db.execute("COMMIT")
            except sqlite3.IntegrityError as exc:
                db.execute("ROLLBACK")
                # The UNIQUE constraint means a genuine replay; other integrity errors
                # are surfaced so they cannot be mistaken for a normal replay denial.
                if "UNIQUE constraint failed" in str(exc):
                    return False
                raise
            except Exception:
                db.execute("ROLLBACK")
                raise

            self.sidecar.commit(counter + 1, updated_nonces)
            return True

    @staticmethod
    def bind_envelope_digest(
        transaction_digest: str,
        alpha: float,
        permitted_delta: float,
        verdict: str,
        authority: Any = None,
    ) -> str:
        """Bind a transaction digest to its Sigilith autonomy envelope and delegation chain."""
        import hashlib
        import json

        canonical = json.dumps(
            {
                "transaction_digest": transaction_digest,
                "alpha": round(float(alpha), 6),
                "permitted_delta": round(float(permitted_delta), 8),
                "verdict": str(verdict),
                "root_principal": str(authority.root_principal) if authority is not None else "UNBOUND",
                "requester_id": str(authority.requester_id) if authority is not None else "UNBOUND",
                "chain_digest": str(authority.chain_digest) if authority is not None else "0" * 64,
            },
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def consume_attenuated(
        self,
        key_id: str,
        nonce: str,
        transaction_digest: str,
        envelope: Any,
        ledger: Any = None,
        action_id: str | None = None,
        proposed_delta: float = 0.0,
        authority: Any = None,
    ) -> tuple[bool, str]:
        """
        Enforce an AutonomyEnvelope and VerifiedAuthorityContext via Guardian's single-use
        replay store and record non-repudiable forensic attribution in TraceGuard.

        HOLD_ESCALATE and FAIL_CLOSED consume zero actuation permits and return (False, bound_digest).
        """
        bound_digest = self.bind_envelope_digest(
            transaction_digest=transaction_digest,
            alpha=envelope.alpha,
            permitted_delta=envelope.permitted_delta,
            verdict=envelope.verdict.value,
            authority=authority,
        )
        if envelope.verdict.value not in ("PERMIT_FULL", "PERMIT_ATTENUATED"):
            if ledger is not None:
                ledger.append(
                    action_id=action_id or f"{key_id}:{nonce}",
                    permit_digest=bound_digest,
                    proposed_delta=proposed_delta,
                    envelope=envelope,
                    authority=authority,
                )
            return False, bound_digest

        accepted = self.consume(key_id, nonce, bound_digest)
        if accepted and ledger is not None:
            ledger.append(
                action_id=action_id or f"{key_id}:{nonce}",
                permit_digest=bound_digest,
                proposed_delta=proposed_delta,
                envelope=envelope,
                authority=authority,
            )
        return accepted, bound_digest
