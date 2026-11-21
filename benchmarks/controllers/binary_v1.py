from typing import List
from benchmarks.types import Decision, StepInput, Verdict


def binary_v1_controller(history: List[StepInput], current: StepInput) -> Decision:
    """V1.0.0 baseline: binary trip to FAIL_CLOSED on drops, jitter, or cumulative drift."""
    if current.corrupt_state:
        return Decision(Verdict.FAIL_CLOSED, 0.0, 0.0, "AXIOMOS_STATE_CORRUPT")
    if current.packet_drop:
        return Decision(Verdict.FAIL_CLOSED, 0.0, 0.0, "AXIOMOS_TELEMETRY_DROP")
    if current.coupled_load >= 0.85:
        return Decision(Verdict.FAIL_CLOSED, 0.0, 0.0, "AXIOMOS_HARD_BOUND")

    cum_bias = sum(x.proposed_delta for x in history[-6:]) + current.proposed_delta
    if abs(cum_bias) > 0.11 or current.sensor_noise > 0.09:
        return Decision(Verdict.FAIL_CLOSED, 0.0, 0.0, "SIGILITH_BINARY_DRIFT")

    return Decision(Verdict.PERMIT_FULL, 1.0, current.proposed_delta, "GUARDIAN_FULL_PERMIT")
