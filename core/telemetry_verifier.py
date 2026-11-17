import time
import math
import json
import os
import threading
import fcntl
from core.verifier_auth import VerifierAuthManager
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

class ReplayProtectedHeartbeatVerifier:
    def __init__(self, node_key_registry: dict, state_file_path: str, ledger_writer=None, max_drift_seconds: float = 30.0, cache_size: int = 1000):
        self.node_key_registry = {k: v for k, v in node_key_registry.items()}
        self.state_file_path = os.fspath(state_file_path)
        self.ledger_writer = ledger_writer
        self.max_drift_seconds = max_drift_seconds
        self.cache_size = cache_size
        self.seen_nonces = {}  # (node_id, nonce) -> timestamp
        self._lock = threading.Lock()

        self._load_persistent_state()

    def _auth_manager(self):
        """Create the authenticated state manager for the telemetry envelope."""
        return VerifierAuthManager(self.state_file_path)

    @staticmethod
    def _nonce_state_key(node_id: str, nonce: str) -> str:
        # JSON encoding avoids delimiter collisions in attacker-controlled identifiers.
        return json.dumps([node_id, nonce], ensure_ascii=False, separators=(",", ":"))

    def _load_persistent_state(self):
        """Load only authenticated state; never parse unauthenticated JSONL history."""
        lock_path = self.state_file_path + ".writer.lock"
        lock_parent = os.path.dirname(os.path.abspath(lock_path))
        os.makedirs(lock_parent, exist_ok=True)
        with open(lock_path, "a+", encoding="utf-8") as lock_file:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_SH)
            try:
                manager = self._auth_manager()
                generation, state_records = manager.load_and_verify()
            finally:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
        timestamps = state_records.get("timestamps", {})
        nonces = state_records.get("nonces", [])
        if not isinstance(timestamps, dict) or not isinstance(nonces, list):
            raise ValueError("Integrity failure: invalid telemetry state record schema")

        loaded = {}
        for key in nonces:
            if not isinstance(key, str) or key not in timestamps:
                raise ValueError("Integrity failure: nonce index and timestamp map disagree")
            try:
                decoded = json.loads(key)
            except (TypeError, json.JSONDecodeError) as exc:
                raise ValueError("Integrity failure: malformed telemetry nonce key") from exc
            if (not isinstance(decoded, list) or len(decoded) != 2 or
                    not all(isinstance(part, str) for part in decoded)):
                raise ValueError("Integrity failure: malformed telemetry nonce identity")
            timestamp = timestamps[key]
            if not isinstance(timestamp, (int, float)) or not math.isfinite(timestamp):
                raise ValueError("Integrity failure: invalid telemetry nonce timestamp")
            if abs(time.time() - timestamp) <= self.max_drift_seconds:
                loaded[(decoded[0], decoded[1])] = float(timestamp)

        # The envelope is the sole persistence authority. A fresh store starts empty.
        self.seen_nonces = loaded
        self._state_generation = generation

    def _persist_atomic_acceptance(self, node_id: str, nonce: str, timestamp: float, signature: str, payload: dict) -> bool:
        """Commit replay state through the authenticated envelope and generation gate."""
        lock_path = self.state_file_path + ".writer.lock"
        lock_parent = os.path.dirname(os.path.abspath(lock_path))
        os.makedirs(lock_parent, exist_ok=True)
        with open(lock_path, "a+", encoding="utf-8") as lock_file:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            try:
                manager = self._auth_manager()
                generation, state_records = manager.load_and_verify()
                current_timestamps = state_records.get("timestamps", {})
                current_nonces = state_records.get("nonces", [])
                if not isinstance(current_timestamps, dict) or not isinstance(current_nonces, list):
                    raise ValueError("Integrity failure: invalid telemetry state record schema")

                nonce_key = self._nonce_state_key(node_id, nonce)
                if nonce_key in current_timestamps or nonce_key in current_nonces:
                    return False

                updated_timestamps = dict(current_timestamps)
                updated_timestamps[nonce_key] = float(timestamp)
                updated_nonces = sorted(set(current_nonces) | {nonce_key})
                manager.commit(generation + 1, {
                    "nonces": updated_nonces,
                    "timestamps": updated_timestamps,
                })
                self._state_generation = generation + 1
                return True
            finally:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)

    def _is_valid_payload(self, obj) -> bool:
        if isinstance(obj, dict):
            return all(isinstance(k, str) and self._is_valid_payload(v) for k, v in obj.items())
        elif isinstance(obj, list):
            return all(self._is_valid_payload(item) for item in obj)
        elif isinstance(obj, (int, float)):
            return math.isfinite(obj)
        elif isinstance(obj, (str, bool, type(None))):
            return True
        return False

    def _canonical_bytes(self, packet: dict) -> bytes:
        payload_subset = {
            "node_id": packet["node_id"],
            "timestamp": packet["timestamp"],
            "nonce": packet["nonce"],
            "payload": packet["payload"]
        }
        return json.dumps(payload_subset, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')

    def verify_and_accept(self, packet: dict) -> bool:
        with self._lock:
            if not isinstance(packet, dict):
                return False
            required_fields = {"node_id", "timestamp", "nonce", "payload", "signature"}
            if not all(field in packet for field in required_fields):
                return False

            node_id = packet["node_id"]
            timestamp = packet["timestamp"]
            nonce = packet["nonce"]
            payload = packet["payload"]
            signature_hex = packet["signature"]

            if not isinstance(node_id, str) or not isinstance(nonce, str) or not isinstance(payload, dict):
                return False
            if not isinstance(timestamp, (int, float)) or not math.isfinite(timestamp):
                return False
            if not isinstance(signature_hex, str):
                return False
            if not self._is_valid_payload(payload):
                return False

            if node_id not in self.node_key_registry:
                return False
            public_key = self.node_key_registry[node_id]

            now = time.time()
            if abs(now - timestamp) > self.max_drift_seconds:
                return False

            nonce_key = (node_id, nonce)
            if nonce_key in self.seen_nonces:
                return False

            self._purge_expired_nonces(now)

            if len(self.seen_nonces) >= self.cache_size:
                return False

            try:
                canonical_data = self._canonical_bytes(packet)
                sig_bytes = bytes.fromhex(signature_hex)
                public_key.verify(sig_bytes, canonical_data)
            except (ValueError, InvalidSignature, TypeError):
                return False

            try:
                committed = self._persist_atomic_acceptance(node_id, nonce, timestamp, signature_hex, payload)
                if not committed:
                    return False
            except OSError:
                return False

            self.seen_nonces[nonce_key] = timestamp
            return True

    def _purge_expired_nonces(self, current_time: float):
        expired = [k for k, t in self.seen_nonces.items() if current_time - t > self.max_drift_seconds]
        for k in expired:
            del self.seen_nonces[k]
