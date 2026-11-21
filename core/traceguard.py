"""
core/traceguard.py: Hash-chained forensic telemetry ledger for attenuated autonomy decisions.

Records (action, permit_digest, H, D, delta, alpha, verdict, executed_delta) in a
tamper-evident SHA-256 hash chain that fails closed if any historical entry is modified.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import time

from core.sigilith import AutonomyEnvelope

GENESIS_HASH = "0" * 64


@dataclass(frozen=True)
class TraceGuardRecord:
    """Single hash-chained audit entry proving bounded autonomy attenuation."""

    seq: int
    timestamp: float
    action_id: str
    permit_digest: str
    verdict: str
    alpha: float
    headroom_pressure: float
    sequence_drift: float
    action_direction: str
    proposed_delta: float
    permitted_delta: float
    reason: str
    prev_hash: str
    entry_hash: str


class TraceGuardLedger:
    """Append-only, fail-closed SHA-256 hash-chained audit ledger."""

    def __init__(self, ledger_path: str | Path) -> None:
        self.path = Path(ledger_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._records: list[TraceGuardRecord] = []
        if self.path.exists():
            self._load_and_verify()

    @staticmethod
    def _compute_entry_hash(payload: dict[str, object]) -> str:
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def _load_and_verify(self) -> None:
        raw_lines = self.path.read_text(encoding="utf-8").splitlines()
        expected_prev = GENESIS_HASH
        loaded: list[TraceGuardRecord] = []

        for idx, line in enumerate(raw_lines):
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"TraceGuard integrity failure: malformed JSON at line {idx}") from exc

            if not isinstance(obj, dict) or "entry_hash" not in obj:
                raise ValueError(f"TraceGuard integrity failure: invalid schema at line {idx}")

            recorded_hash = obj["entry_hash"]
            unsigned = {k: v for k, v in obj.items() if k != "entry_hash"}
            if unsigned.get("seq") != idx or unsigned.get("prev_hash") != expected_prev:
                raise ValueError(f"TraceGuard integrity failure: broken sequence/prev_hash at line {idx}")

            actual_hash = self._compute_entry_hash(unsigned)
            if actual_hash != recorded_hash:
                raise ValueError(f"TraceGuard integrity failure: hash mismatch at line {idx}")

            loaded.append(
                TraceGuardRecord(
                    seq=int(unsigned["seq"]),
                    timestamp=float(unsigned["timestamp"]),
                    action_id=str(unsigned["action_id"]),
                    permit_digest=str(unsigned["permit_digest"]),
                    verdict=str(unsigned["verdict"]),
                    alpha=float(unsigned["alpha"]),
                    headroom_pressure=float(unsigned["headroom_pressure"]),
                    sequence_drift=float(unsigned["sequence_drift"]),
                    action_direction=str(unsigned["action_direction"]),
                    proposed_delta=float(unsigned["proposed_delta"]),
                    permitted_delta=float(unsigned["permitted_delta"]),
                    reason=str(unsigned["reason"]),
                    prev_hash=str(unsigned["prev_hash"]),
                    entry_hash=str(recorded_hash),
                )
            )
            expected_prev = actual_hash

        self._records = loaded

    @property
    def records(self) -> list[TraceGuardRecord]:
        return list(self._records)

    @property
    def head_hash(self) -> str:
        return self._records[-1].entry_hash if self._records else GENESIS_HASH

    def append(
        self,
        action_id: str,
        permit_digest: str,
        proposed_delta: float,
        envelope: AutonomyEnvelope,
        timestamp: float | None = None,
    ) -> TraceGuardRecord:
        """Append a cryptographically chained autonomy attenuation record."""
        seq = len(self._records)
        ts = float(timestamp) if timestamp is not None else time.time()
        prev_hash = self.head_hash
        unsigned: dict[str, object] = {
            "seq": seq,
            "timestamp": ts,
            "action_id": action_id,
            "permit_digest": permit_digest,
            "verdict": envelope.verdict.value,
            "alpha": envelope.alpha,
            "headroom_pressure": envelope.headroom_pressure,
            "sequence_drift": envelope.sequence_drift,
            "action_direction": envelope.action_direction,
            "proposed_delta": float(proposed_delta),
            "permitted_delta": float(envelope.permitted_delta),
            "reason": envelope.reason,
            "prev_hash": prev_hash,
        }
        entry_hash = self._compute_entry_hash(unsigned)
        full_entry = dict(unsigned, entry_hash=entry_hash)

        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(full_entry, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n")
            fh.flush()
            os.fsync(fh.fileno())

        rec = TraceGuardRecord(
            seq=seq,
            timestamp=ts,
            action_id=action_id,
            permit_digest=permit_digest,
            verdict=envelope.verdict.value,
            alpha=envelope.alpha,
            headroom_pressure=envelope.headroom_pressure,
            sequence_drift=envelope.sequence_drift,
            action_direction=envelope.action_direction,
            proposed_delta=float(proposed_delta),
            permitted_delta=float(envelope.permitted_delta),
            reason=envelope.reason,
            prev_hash=prev_hash,
            entry_hash=entry_hash,
        )
        self._records.append(rec)
        return rec
