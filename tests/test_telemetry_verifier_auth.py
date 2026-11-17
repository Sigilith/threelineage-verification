import json
import time

import pytest

from core.telemetry_verifier import ReplayProtectedHeartbeatVerifier
from core.verifier_auth import VerifierAuthManager


class AcceptingPublicKey:
    def verify(self, signature, message):
        return None


def packet(nonce):
    return {
        "node_id": "node-test",
        "timestamp": time.time(),
        "nonce": nonce,
        "payload": {"sequence": 1},
        "signature": "00" * 64,
    }


def verifier(path):
    return ReplayProtectedHeartbeatVerifier(
        node_key_registry={"node-test": AcceptingPublicKey()},
        state_file_path=str(path),
        max_drift_seconds=3600,
    )


def test_telemetry_state_persists_through_authenticated_envelope(tmp_path):
    state_path = tmp_path / "telemetry.state"
    first = verifier(state_path)
    assert first.verify_and_accept(packet("nonce-a")) is True

    generation, records = VerifierAuthManager(state_path).load_and_verify()
    assert generation == 1
    assert len(records["nonces"]) == 1

    restarted = verifier(state_path)
    assert ("node-test", "nonce-a") in restarted.seen_nonces
    assert restarted.verify_and_accept(packet("nonce-a")) is False


def test_telemetry_envelope_tampering_fails_closed(tmp_path):
    state_path = tmp_path / "telemetry.state"
    assert verifier(state_path).verify_and_accept(packet("nonce-original")) is True

    envelope = json.loads(state_path.read_text(encoding="utf-8"))
    key = envelope["state_records"]["nonces"][0]
    envelope["state_records"]["nonces"][0] = key.replace("nonce-original", "nonce-forged")
    state_path.write_text(json.dumps(envelope), encoding="utf-8")

    with pytest.raises(ValueError, match="HMAC signature mismatch|State hash mismatch"):
        verifier(state_path)


def test_telemetry_generation_increments_for_each_acceptance(tmp_path):
    state_path = tmp_path / "telemetry.state"
    instance = verifier(state_path)
    assert instance.verify_and_accept(packet("nonce-a")) is True
    assert instance.verify_and_accept(packet("nonce-b")) is True
    generation, records = VerifierAuthManager(state_path).load_and_verify()
    assert generation == 2
    assert len(records["nonces"]) == 2
