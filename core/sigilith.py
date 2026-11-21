"""
core/sigilith.py: Continuous autonomy-pressure engine computing alpha = f(H, D, Delta).

Separates inviolable binary AXIOMOS safety perimeters from continuous uncertainty
attenuation inside the remaining verified headroom envelope.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum
import math


class GovernanceVerdict(str, Enum):
    """Four-state deterministic execution spectrum."""

    PERMIT_FULL = "PERMIT_FULL"
    PERMIT_ATTENUATED = "PERMIT_ATTENUATED"
    HOLD_ESCALATE = "HOLD_ESCALATE"
    FAIL_CLOSED = "FAIL_CLOSED"


@dataclass(frozen=True)
class AutonomyEnvelope:
    """Attenuated authority envelope issued by Sigilith and enforced by Guardian."""

    verdict: GovernanceVerdict
    alpha: float
    headroom_pressure: float
    sequence_drift: float
    action_direction: str
    permitted_delta: float
    reason: str


class SigilithAutonomyEngine:
    """
    Behavioural trajectory and autonomy-pressure evaluator: alpha = f(H, D, Delta).

    - AXIOMOS hard bounds and state integrity remain strictly binary (FAIL_CLOSED).
    - Stabilizing actions that restore safety margin receive full authority (alpha = 1.0),
      attenuated slightly only under high telemetry uncertainty.
    - Destabilizing actions approaching the perimeter scale down smoothly via alpha in [0.20, 1.0],
      escalating to HOLD_ESCALATE before crossing the hard AXIOMOS boundary.
    """

    def __init__(
        self,
        nominal_state: float = 0.45,
        headroom_floor: float = 0.50,
        hard_bound: float = 0.90,
        drift_window: int = 8,
        drift_scale: float = 0.24,
        noise_scale: float = 0.15,
    ) -> None:
        if not (nominal_state <= headroom_floor < hard_bound):
            raise ValueError("Invalid safety envelope bounds: require nominal <= floor < hard_bound")
        self.nominal_state = nominal_state
        self.headroom_floor = headroom_floor
        self.hard_bound = hard_bound
        self.drift_window = drift_window
        self.drift_scale = drift_scale
        self.noise_scale = noise_scale

    def evaluate(
        self,
        current_state: float,
        proposed_delta: float,
        recent_deltas: Sequence[float] = (),
        sensor_noise: float = 0.0,
        packet_drop: bool = False,
        corrupt_state: bool = False,
    ) -> AutonomyEnvelope:
        """Compute risk-proportional authority scalar alpha = f(H, D, Delta)."""
        if (
            corrupt_state
            or not math.isfinite(current_state)
            or not math.isfinite(proposed_delta)
            or not math.isfinite(sensor_noise)
        ):
            return AutonomyEnvelope(
                verdict=GovernanceVerdict.FAIL_CLOSED,
                alpha=0.0,
                headroom_pressure=1.0,
                sequence_drift=0.0,
                action_direction="INVALID_OR_CORRUPT",
                permitted_delta=0.0,
                reason="AXIOMOS_STATE_CORRUPT",
            )

        if current_state >= self.hard_bound:
            return AutonomyEnvelope(
                verdict=GovernanceVerdict.FAIL_CLOSED,
                alpha=0.0,
                headroom_pressure=1.0,
                sequence_drift=abs(sum(recent_deltas[-self.drift_window :]) + proposed_delta),
                action_direction="BREACH_PERIMETER",
                permitted_delta=0.0,
                reason="AXIOMOS_HARD_BOUND",
            )

        deviation = current_state - self.nominal_state
        is_stabilizing = (deviation * proposed_delta) < 0.0
        direction = "STABILIZING" if is_stabilizing else ("NEUTRAL" if proposed_delta == 0.0 else "DESTABILIZING")

        H = max(0.0, (current_state - self.headroom_floor) / (self.hard_bound - self.headroom_floor))
        window = list(recent_deltas[-self.drift_window :]) + [proposed_delta]
        D = abs(sum(window))

        if is_stabilizing:
            if sensor_noise > 0.10 or packet_drop:
                alpha = 0.80
                return AutonomyEnvelope(
                    verdict=GovernanceVerdict.PERMIT_ATTENUATED,
                    alpha=alpha,
                    headroom_pressure=round(H, 6),
                    sequence_drift=round(D, 6),
                    action_direction=direction,
                    permitted_delta=proposed_delta * alpha,
                    reason="GUARDIAN_NOISY_RECOVERY",
                )
            return AutonomyEnvelope(
                verdict=GovernanceVerdict.PERMIT_FULL,
                alpha=1.0,
                headroom_pressure=round(H, 6),
                sequence_drift=round(D, 6),
                action_direction=direction,
                permitted_delta=proposed_delta,
                reason="GUARDIAN_STABILIZING_PERMIT",
            )

        drift_ratio = min(1.5, D / self.drift_scale)
        uncertainty = min(1.0, (max(0.0, sensor_noise) / self.noise_scale) + (0.25 if packet_drop else 0.0))

        if H >= 0.90 or (H >= 0.62 and drift_ratio >= 0.85):
            return AutonomyEnvelope(
                verdict=GovernanceVerdict.HOLD_ESCALATE,
                alpha=0.0,
                headroom_pressure=round(H, 6),
                sequence_drift=round(D, 6),
                action_direction=direction,
                permitted_delta=0.0,
                reason="SIGILITH_PERIMETER_ESCALATION",
            )

        if H >= 0.80:
            alpha = max(
                0.20,
                round(1.0 - (0.75 * H + 0.15 * min(1.0, drift_ratio) + 0.10 * uncertainty), 3),
            )
            return AutonomyEnvelope(
                verdict=GovernanceVerdict.PERMIT_ATTENUATED,
                alpha=alpha,
                headroom_pressure=round(H, 6),
                sequence_drift=round(D, 6),
                action_direction=direction,
                permitted_delta=proposed_delta * alpha,
                reason=f"GUARDIAN_DERATED_ALPHA_{alpha}",
            )

        risk_score = (0.45 * H) + (0.40 * min(1.0, drift_ratio)) + (0.15 * uncertainty)
        if risk_score > 0.20:
            alpha = max(0.25, round(1.0 - risk_score, 3))
            return AutonomyEnvelope(
                verdict=GovernanceVerdict.PERMIT_ATTENUATED,
                alpha=alpha,
                headroom_pressure=round(H, 6),
                sequence_drift=round(D, 6),
                action_direction=direction,
                permitted_delta=proposed_delta * alpha,
                reason=f"GUARDIAN_DERATED_ALPHA_{alpha}",
            )

        return AutonomyEnvelope(
            verdict=GovernanceVerdict.PERMIT_FULL,
            alpha=1.0,
            headroom_pressure=round(H, 6),
            sequence_drift=round(D, 6),
            action_direction=direction,
            permitted_delta=proposed_delta,
            reason="GUARDIAN_FULL_PERMIT",
        )
