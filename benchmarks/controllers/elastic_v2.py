"""State-coupled elastic governance controller: alpha = f(H, D, Delta)."""

from __future__ import annotations

from benchmarks.types import Decision, StepInput, Verdict

NOMINAL_LOAD = 0.45
HEADROOM_FLOOR = 0.50
HARD_LOAD_BOUND = 0.90
DRIFT_WINDOW = 8
DRIFT_SCALE = 0.24
NOISE_SCALE = 0.15


def elastic_v2_controller(history: list[StepInput], current: StepInput) -> Decision:
    """Preserve binary AXIOMOS invariants while scaling permit authority inside headroom."""
    if current.corrupt_state:
        return Decision(Verdict.FAIL_CLOSED, 0.0, 0.0, "AXIOMOS_STATE_CORRUPT")
    if current.coupled_load >= HARD_LOAD_BOUND:
        return Decision(Verdict.FAIL_CLOSED, 0.0, 0.0, "AXIOMOS_HARD_BOUND")

    deviation = current.coupled_load - NOMINAL_LOAD
    is_stabilizing = (deviation * current.proposed_delta) < 0.0

    if is_stabilizing:
        if current.sensor_noise > 0.10 or current.packet_drop:
            return Decision(
                Verdict.PERMIT_ATTENUATED,
                0.80,
                current.proposed_delta * 0.80,
                "GUARDIAN_NOISY_RECOVERY",
            )
        return Decision(Verdict.PERMIT_FULL, 1.0, current.proposed_delta, "GUARDIAN_STABILIZING_PERMIT")

    headroom_pressure = max(0.0, (current.coupled_load - HEADROOM_FLOOR) / (HARD_LOAD_BOUND - HEADROOM_FLOOR))
    window = [x.proposed_delta for x in history[-DRIFT_WINDOW:]] + [current.proposed_delta]
    directional_drift = abs(sum(window))
    drift_ratio = min(1.5, directional_drift / DRIFT_SCALE)
    uncertainty = min(1.0, (current.sensor_noise / NOISE_SCALE) + (0.25 if current.packet_drop else 0.0))

    if headroom_pressure >= 0.90 or (headroom_pressure >= 0.62 and drift_ratio >= 0.85):
        return Decision(Verdict.HOLD_ESCALATE, 0.0, 0.0, "SIGILITH_PERIMETER_ESCALATION")

    if headroom_pressure >= 0.80:
        alpha = max(
            0.20,
            round(1.0 - (0.75 * headroom_pressure + 0.15 * min(1.0, drift_ratio) + 0.10 * uncertainty), 3),
        )
        return Decision(
            Verdict.PERMIT_ATTENUATED,
            alpha,
            current.proposed_delta * alpha,
            f"GUARDIAN_DERATED_ALPHA_{alpha}",
        )

    risk_score = (0.45 * headroom_pressure) + (0.40 * min(1.0, drift_ratio)) + (0.15 * uncertainty)
    if risk_score > 0.20:
        alpha = max(0.25, round(1.0 - risk_score, 3))
        return Decision(
            Verdict.PERMIT_ATTENUATED,
            alpha,
            current.proposed_delta * alpha,
            f"GUARDIAN_DERATED_ALPHA_{alpha}",
        )

    return Decision(Verdict.PERMIT_FULL, 1.0, current.proposed_delta, "GUARDIAN_FULL_PERMIT")
