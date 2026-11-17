#!/usr/bin/env python3
"""
core/auth_sidecar.py: Cryptographic Sidecar for SQLiteReplayStore (TL-FIND-001 Mitigation)
Provides HMAC-SHA256 integrity binding, monotonic counter enforcement, and atomic commits.
"""

import os
import json
import hmac
import hashlib
from pathlib import Path

def get_hmac_secret() -> bytes:
    env_secret = os.environ.get("GUARDIAN_HMAC_SECRET")
    if not env_secret:
        raise ValueError("GUARDIAN_HMAC_SECRET is required; no fallback secret is permitted")
    secret = env_secret.encode("utf-8")
    if len(secret) < 32:
        raise ValueError("GUARDIAN_HMAC_SECRET must contain at least 32 UTF-8 bytes")
    return secret

def compute_state_hash(nonces: list) -> str:
    """
    Computes a deterministic SHA-256 hash over the sorted collection of active consumed nonces.
    Ensures row deletion or substitution invalidates the state hash.
    """
    sorted_nonces = sorted(str(n) for n in nonces)
    h = hashlib.sha256()
    for nonce in sorted_nonces:
        h.update(nonce.encode("utf-8"))
    return h.hexdigest()

def compute_hmac(version: int, monotonic_counter: int, state_hash: str, secret: bytes) -> str:
    payload = f"{version}:{monotonic_counter}:{state_hash}".encode("utf-8")
    return hmac.new(secret, payload, hashlib.sha256).hexdigest()

class AuthSidecarManager:
    def __init__(self, db_path: str):
        self.db_path = Path(db_path)
        self.sidecar_path = Path(str(db_path) + ".auth.json")
        self.secret = get_hmac_secret()

    def exists(self) -> bool:
        return self.sidecar_path.exists()

    def load_and_verify(self, current_nonces: list) -> int:
        """
        Loads the sidecar, verifies the HMAC signature, and verifies that the computed
        state hash matches the actual nonces present in the database.
        Returns the verified monotonic counter on success.
        Raises ValueError / PermissionError on integrity failure (Fail-Closed).
        """
        if not self.sidecar_path.exists():
            raise ValueError(f"Integrity failure: Missing authentication sidecar for {self.db_path}")

        try:
            with open(self.sidecar_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            raise ValueError(f"Integrity failure: Corrupt sidecar JSON: {e}")

        version = data.get("version", 1)
        counter = data.get("monotonic_counter")
        stored_state_hash = data.get("state_hash")
        stored_hmac = data.get("hmac_signature")

        if counter is None or stored_state_hash is None or stored_hmac is None:
            raise ValueError("Integrity failure: Incomplete sidecar schema fields")

        # 1. Verify HMAC signature
        expected_hmac = compute_hmac(version, counter, stored_state_hash, self.secret)
        if not hmac.compare_digest(expected_hmac, stored_hmac):
            raise ValueError("Integrity failure: HMAC signature mismatch (tampering or wrong key)")

        # 2. Verify state hash matches database contents
        actual_state_hash = compute_state_hash(current_nonces)
        if not hmac.compare_digest(actual_state_hash, stored_state_hash):
            raise ValueError("Integrity failure: State hash mismatch (unauthorized row deletion, insertion, or substitution)")

        return counter

    def commit(self, new_counter: int, current_nonces: list):
        """
        Atomically commits an updated sidecar file with a new monotonic counter and state hash.
        """
        state_hash = compute_state_hash(current_nonces)
        version = 1
        hmac_sig = compute_hmac(version, new_counter, state_hash, self.secret)

        sidecar_data = {
            "version": version,
            "monotonic_counter": new_counter,
            "state_hash": state_hash,
            "hmac_signature": hmac_sig
        }

        temp_path = self.sidecar_path.with_suffix(".tmp")
        with open(temp_path, "w", encoding="utf-8") as f:
            json.dump(sidecar_data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())

        # Atomic rename
        os.replace(temp_path, self.sidecar_path)
