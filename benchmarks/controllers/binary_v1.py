"""V1.0.0 binary governance baseline controller."""

from __future__ import annotations

from benchmarks.types import Decision, StepInput, Verdict

HARD_LOAD_BOUND = 0.85
DRIFT_WINDOW = 6
MAX_CUMULATIVE_BIAS = 0.11
MAX_SENSOR_NOISE = 0.09


def binary_v1_controller(history: list[StepInput], current: StepInput) -> Decision:
    """Trip immediately to FAIL_CLOSED on drops, jitter, drift, or hard-bound approach."""
    if current.corrupt_state:
        return Decision(Verdict.FAIL_CLOSED, 0.0, 0.0, "AXIOMOS_STATE_CORRUPT")
    if current.packet_drop:
        return Decision(Verdict.FAIL_CLOSED, 0.0, 0.0, "AXIOMOS_TELEMETRY_DROP")
    if current.coupled_load >= HARD_LOAD_BOUND:
        return Decision(Verdict.FAIL_CLOSED, 0.0, 0.0, "AXIOMOS_HARD_BOUND")

    cum_bias = sum(x.proposed_delta for x in history[-DRIFT_WINDOW:]) + current.proposed_delta
    if abs(cum_bias) > MAX_CUMULATIVE_BIAS or current.sensor_noise > MAX_SENSOR_NOISE:
        return Decision(Verdict.FAIL_CLOSED, 0.0, 0.0, "SIGILITH_BINARY_DRIFT")

    return Decision(Verdict.PERMIT_FULL, 1.0, current.proposed_delta, "GUARDIAN_FULL_PERMIT")
