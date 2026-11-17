#!/usr/bin/env python3
"""
core/verifier_auth.py: Cryptographic Verifier Authentication & Freshness Anchor (TL-FIND-002 Mitigation)
Implements a canonical authenticated state envelope with an adjacent local generation marker.
"""

import os
import json
import hmac
import hashlib
from pathlib import Path
from typing import Dict, Any, Tuple

def get_verifier_secret() -> bytes:
    env_secret = os.environ.get("VERIFIER_HMAC_SECRET")
    if not env_secret:
        raise ValueError("VERIFIER_HMAC_SECRET is required; no fallback secret is permitted")
    secret = env_secret.encode("utf-8")
    if len(secret) < 32:
        raise ValueError("VERIFIER_HMAC_SECRET must contain at least 32 UTF-8 bytes")
    return secret

def compute_state_hash(state_records: Dict[str, Any]) -> str:
    """
    Computes a deterministic SHA-256 hash over canonical state records (nonces and timestamps).
    """
    canonical_data = {
        "nonces": sorted(str(n) for n in state_records.get("nonces", [])),
        "timestamps": {str(k): float(v) for k, v in sorted(state_records.get("timestamps", {}).items())}
    }
    encoded = json.dumps(canonical_data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()

def compute_envelope_hmac(format_version: int, generation: int, state_hash: str, secret: bytes) -> str:
    payload = f"{format_version}:{generation}:{state_hash}".encode("utf-8")
    return hmac.new(secret, payload, hashlib.sha256).hexdigest()

class VerifierAuthManager:
    def __init__(self, state_path: str | Path):
        self.state_path = Path(state_path)
        self.anchor_path = Path(str(state_path) + ".lock")
        self.secret = get_verifier_secret()

    def _read_anchor(self) -> int:
        if not self.anchor_path.exists():
            return -1
        try:
            with open(self.anchor_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            value = data.get("max_generation")
            if type(value) is not int or value < 0:
                raise ValueError("Invalid max_generation in freshness anchor")
            return value
        except (OSError, json.JSONDecodeError, TypeError, AttributeError) as exc:
            raise ValueError(f"Integrity failure: unreadable freshness anchor: {exc}") from exc

    def _write_anchor(self, generation: int):
        temp_path = self.anchor_path.with_suffix(".tmp")
        with open(temp_path, "w", encoding="utf-8") as f:
            json.dump({"max_generation": generation}, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_path, self.anchor_path)

    def load_and_verify(self) -> Tuple[int, Dict[str, Any]]:
        """
        Loads the canonical state envelope, verifies HMAC signature, verifies state hash,
        and enforces consistency with the adjacent local generation marker.
        Returns (generation, state_records) on success.
        Raises ValueError on any integrity or freshness violation (Fail-Closed).
        """
        state_exists = self.state_path.exists()
        anchor_exists = self.anchor_path.exists()

        # First-run vs deleted-state distinction
        if not state_exists and not anchor_exists:
            return 0, {"nonces": [], "timestamps": {}}

        if not state_exists or not anchor_exists:
            raise ValueError("Integrity failure: Split-brain state/anchor erasure detected (missing component)")

        max_seen_gen = self._read_anchor()
        if max_seen_gen < 0:
            raise ValueError("Integrity failure: Corrupt or uninitialized freshness anchor")

        try:
            with open(self.state_path, "r", encoding="utf-8") as f:
                envelope = json.load(f)
        except Exception as e:
            raise ValueError(f"Integrity failure: Corrupt state envelope JSON: {e}")

        if not isinstance(envelope, dict):
            raise ValueError("Integrity failure: state envelope must be an object")
        format_version = envelope.get("format_version", 1)
        generation = envelope.get("generation")
        state_records = envelope.get("state_records")
        stored_state_hash = envelope.get("state_hash")
        stored_hmac = envelope.get("hmac_signature")

        if generation is None or state_records is None or stored_state_hash is None or stored_hmac is None:
            raise ValueError("Integrity failure: Incomplete state envelope schema fields")

        if type(format_version) is not int or format_version != 1:
            raise ValueError("Integrity failure: unsupported state envelope format_version")
        if type(generation) is not int or generation < 1:
            raise ValueError("Integrity failure: invalid state envelope generation")
        if not isinstance(state_records, dict):
            raise ValueError("Integrity failure: state_records must be an object")

        # 1. Require the envelope and adjacent local marker to describe the same
        # committed generation. A state-ahead marker indicates interrupted
        # publication and is fail-closed, not silently accepted or auto-repaired.
        if generation < max_seen_gen:
            raise ValueError(f"Integrity failure: Generation regression detected ({generation} < anchored max {max_seen_gen}) - Rollback rejected")
        if generation > max_seen_gen:
            raise ValueError(
                f"Integrity failure: State generation ahead of freshness marker ({generation} > {max_seen_gen}); administrative reconciliation required"
            )

        # 2. Verify HMAC Signature
        expected_hmac = compute_envelope_hmac(format_version, generation, stored_state_hash, self.secret)
        if not hmac.compare_digest(expected_hmac, stored_hmac):
            raise ValueError("Integrity failure: HMAC signature mismatch on state envelope")

        # 3. Verify State Hash (Content Integrity)
        computed_state_hash = compute_state_hash(state_records)
        if not hmac.compare_digest(computed_state_hash, stored_state_hash):
            raise ValueError("Integrity failure: State hash mismatch - record substitution, deletion, or insertion detected")

        return generation, state_records

    def commit(self, new_generation: int, state_records: Dict[str, Any]):
        """
        Publishes a new authenticated state envelope and local freshness marker.

        The adjacent marker is not an independent or rollback-proof anchor: an attacker
        able to restore both files can restore an older pair. See SECURITY.md.
        """
        if type(new_generation) is not int or new_generation < 1:
            raise ValueError("new_generation must be a positive integer")
        current_generation, _ = self.load_and_verify()
        if new_generation <= current_generation:
            raise ValueError(
                f"Generation must increase strictly ({new_generation} <= current {current_generation})"
            )

        format_version = 1
        state_hash = compute_state_hash(state_records)
        hmac_signature = compute_envelope_hmac(format_version, new_generation, state_hash, self.secret)

        envelope = {
            "format_version": format_version,
            "generation": new_generation,
            "created_at": __import__("time").time(),
            "state_records": state_records,
            "state_hash": state_hash,
            "hmac_signature": hmac_signature
        }

        temp_state_path = self.state_path.with_suffix(".tmp")
        with open(temp_state_path, "w", encoding="utf-8") as f:
            json.dump(envelope, f, indent=2)
            f.flush()
            os.fsync(f.fileno())

        os.replace(temp_state_path, self.state_path)
        self._write_anchor(new_generation)
