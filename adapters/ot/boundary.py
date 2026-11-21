"""
adapters/ot/boundary.py: Non-actuating OT boundary normalization and delta-clamping scaffold.

Translates normalized industrial telemetry and proposed setpoint deltas into
SigilithAutonomyEngine evaluations while preserving explicit non-actuating semantics
and yielding to hardware safety/quality boundaries.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
import math
from typing import Literal

from core.sigilith import AutonomyEnvelope, GovernanceVerdict, SigilithAutonomyEngine

ProtocolName = Literal["OPC-UA", "DNP3", "IEC-61850", "GENERIC-OT"]


@dataclass(frozen=True)
class OTTelemetryFrame:
    """Normalized industrial telemetry point snapshot at an OT boundary."""

    protocol: ProtocolName
    zone_id: str
    point_id: str
    normalized_state: float
    sensor_noise: float = 0.0
    packet_drop: bool = False
    quality_good: bool = True
    hardware_sis_trip: bool = False


@dataclass(frozen=True)
class OTBoundaryDecision:
    """Non-actuating evaluation output produced at the OT boundary."""

    actuation_permitted: bool
    non_actuating_only: bool
    protocol: ProtocolName
    zone_id: str
    point_id: str
    proposed_delta: float
    clamped_delta: float
    envelope: AutonomyEnvelope


class NonActuatingOTBoundaryAdapter:
    """Evaluates OT telemetry and proposed setpoint changes without performing physical actuation."""

    def __init__(self, engine: SigilithAutonomyEngine | None = None) -> None:
        self.engine = engine or SigilithAutonomyEngine()

    def evaluate_proposal(
        self,
        frame: OTTelemetryFrame,
        proposed_delta: float,
        recent_deltas: Sequence[float] = (),
        max_alpha_cap: float = 1.0,
    ) -> OTBoundaryDecision:
        """Compute a clamped, non-actuating setpoint proposal for a telemetry frame."""
        corrupt_state = (not frame.quality_good) or frame.hardware_sis_trip
        envelope = self.engine.evaluate(
            current_state=frame.normalized_state,
            proposed_delta=proposed_delta,
            recent_deltas=recent_deltas,
            sensor_noise=frame.sensor_noise,
            packet_drop=frame.packet_drop,
            corrupt_state=corrupt_state,
            max_alpha_cap=max_alpha_cap,
        )

        if frame.hardware_sis_trip or not frame.quality_good:
            clamped_delta = 0.0
            permitted = False
        elif envelope.verdict in (GovernanceVerdict.PERMIT_FULL, GovernanceVerdict.PERMIT_ATTENUATED):
            raw_clamped = float(envelope.permitted_delta)
            clamped_delta = raw_clamped if math.isfinite(raw_clamped) else 0.0
            permitted = True
        else:
            clamped_delta = 0.0
            permitted = False

        return OTBoundaryDecision(
            actuation_permitted=permitted,
            non_actuating_only=True,
            protocol=frame.protocol,
            zone_id=frame.zone_id,
            point_id=frame.point_id,
            proposed_delta=float(proposed_delta),
            clamped_delta=clamped_delta,
            envelope=envelope,
        )
