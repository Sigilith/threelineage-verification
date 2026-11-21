"""
core/hardware_trust.py: Interfaces and reference test doubles for hardware-anchored trust.

Defines explicit contracts for:
- MonotonicCounterProvider (TPM-backed or hardware-anchored monotonic counters)
- HSMRootProvider (HSM-rooted signing/attestation roots)
- TransparencyLogAnchor (external append-only transparency log or witness checkpoints)
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
import hashlib
import json
from typing import Protocol


@dataclass(frozen=True)
class CounterAttestation:
    """Monotonic counter reading returned by a hardware or test counter provider."""

    counter_id: str
    value: int
    attestation_digest: str


@dataclass(frozen=True)
class WitnessCheckpoint:
    """External transparency log checkpoint sealing a ledger or delegation digest."""

    log_id: str
    ledger_head_hash: str
    chain_digest: str
    checkpoint_seq: int
    checkpoint_digest: str


class MonotonicCounterProvider(ABC):
    """Abstract contract for monotonically increasing, non-rollbackable counters."""

    @abstractmethod
    def current_value(self, counter_id: str) -> int:
        """Return the current persisted monotonic counter value."""

    @abstractmethod
    def advance(self, counter_id: str, min_step: int = 1) -> CounterAttestation:
        """Advance the counter monotonically by at least min_step."""


class HSMRootProvider(ABC):
    """Abstract contract for hardware-protected key roots and signatures."""

    @abstractmethod
    def key_id(self) -> str:
        """Return identifier of the hardware-protected key root."""

    @abstractmethod
    def sign_digest(self, digest_hex: str) -> str:
        """Produce a deterministic signature or attestation tag over a hex digest."""

    @abstractmethod
    def verify_digest_signature(self, digest_hex: str, signature_hex: str) -> bool:
        """Verify a signature or attestation tag over a hex digest."""


class TransparencyLogAnchor(ABC):
    """Abstract contract for publishing and verifying external witness checkpoints."""

    @abstractmethod
    def publish_checkpoint(self, ledger_head_hash: str, chain_digest: str) -> WitnessCheckpoint:
        """Publish a checkpoint linking ledger state and delegation chain digest."""

    @abstractmethod
    def verify_checkpoint(self, checkpoint: WitnessCheckpoint) -> bool:
        """Verify checkpoint digest integrity and sequence consistency."""


class ClockLike(Protocol):
    def now(self) -> float: ...


class InMemoryMonotonicCounter(MonotonicCounterProvider):
    """Deterministic in-memory monotonic counter double for unit and integration testing."""

    def __init__(self, initial_value: int = 0) -> None:
        if initial_value < 0:
            raise ValueError("initial_value must be non-negative")
        self._counters: dict[str, int] = {}
        self._default_initial = initial_value

    def current_value(self, counter_id: str) -> int:
        return self._counters.get(counter_id, self._default_initial)

    def advance(self, counter_id: str, min_step: int = 1) -> CounterAttestation:
        if min_step < 1:
            raise ValueError("min_step must be at least 1")
        next_val = self.current_value(counter_id) + min_step
        self._counters[counter_id] = next_val
        digest = hashlib.sha256(f"{counter_id}:{next_val}".encode("utf-8")).hexdigest()
        return CounterAttestation(counter_id=counter_id, value=next_val, attestation_digest=digest)


class ReferenceHSMRoot(HSMRootProvider):
    """Keyed HMAC-SHA256 test double modeling an isolated HSM signing root."""

    def __init__(self, hsm_key_id: str, root_secret: bytes) -> None:
        if not hsm_key_id or not root_secret:
            raise ValueError("hsm_key_id and root_secret must be non-empty")
        self._key_id = hsm_key_id
        self._secret = bytes(root_secret)

    def key_id(self) -> str:
        return self._key_id

    def sign_digest(self, digest_hex: str) -> str:
        msg = f"{self._key_id}:{digest_hex}".encode("utf-8")
        return hashlib.blake2b(msg, key=self._secret[:32], digest_size=32).hexdigest()

    def verify_digest_signature(self, digest_hex: str, signature_hex: str) -> bool:
        expected = self.sign_digest(digest_hex)
        return len(expected) == len(signature_hex) and _constant_time_eq(expected, signature_hex)


def _constant_time_eq(a: str, b: str) -> bool:
    if len(a) != len(b):
        return False
    diff = 0
    for x, y in zip(a.encode("utf-8"), b.encode("utf-8")):
        diff |= x ^ y
    return diff == 0


class InMemoryTransparencyLog(TransparencyLogAnchor):
    """Append-only witness checkpoint log double for verifying external anchoring."""

    def __init__(self, log_id: str = "witness-log-01") -> None:
        self.log_id = log_id
        self.checkpoints: list[WitnessCheckpoint] = []

    def publish_checkpoint(self, ledger_head_hash: str, chain_digest: str) -> WitnessCheckpoint:
        seq = len(self.checkpoints) + 1
        prev_cp_digest = self.checkpoints[-1].checkpoint_digest if self.checkpoints else ("0" * 64)
        payload = json.dumps(
            {
                "log_id": self.log_id,
                "seq": seq,
                "ledger_head_hash": ledger_head_hash,
                "chain_digest": chain_digest,
                "prev_checkpoint_digest": prev_cp_digest,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        cp_digest = hashlib.sha256(payload).hexdigest()
        cp = WitnessCheckpoint(
            log_id=self.log_id,
            ledger_head_hash=ledger_head_hash,
            chain_digest=chain_digest,
            checkpoint_seq=seq,
            checkpoint_digest=cp_digest,
        )
        self.checkpoints.append(cp)
        return cp

    def verify_checkpoint(self, checkpoint: WitnessCheckpoint) -> bool:
        if checkpoint.checkpoint_seq < 1 or checkpoint.checkpoint_seq > len(self.checkpoints):
            return False
        stored = self.checkpoints[checkpoint.checkpoint_seq - 1]
        return stored == checkpoint
