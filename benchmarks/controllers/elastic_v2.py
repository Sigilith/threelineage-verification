from typing import List
from benchmarks.types import Decision, StepInput, Verdict


def elastic_v2_controller(history: List[StepInput], current: StepInput) -> Decision:
    """
    Risk-proportional adaptive governance: alpha = f(H, D, Delta)
    - AXIOMOS: Hard state-integrity and physical bounds remain strictly binary.
    - Sigilith: Evaluates headroom (H), directional drift (D), and action vector (Delta).
    - Guardian: Attenuates permit authority smoothly via scalar alpha in [0.20, 1.0].
    """
    nominal_load = 0.45
    hard_bound = 0.90

    # 1. Hard AXIOMOS invariants (inviolable)
    if current.corrupt_state:
        return Decision(Verdict.FAIL_CLOSED, 0.0, 0.0, "AXIOMOS_STATE_CORRUPT")
    if current.coupled_load >= hard_bound:
        return Decision(Verdict.FAIL_CLOSED, 0.0, 0.0, "AXIOMOS_HARD_BOUND")

    deviation = current.coupled_load - nominal_load
    is_stabilizing = (deviation * current.proposed_delta) < 0.0

    # 2. Case A: Corrective action moving toward nominal restores safety margin
    if is_stabilizing:
        if current.sensor_noise > 0.10 or current.packet_drop:
            return Decision(Verdict.PERMIT_ATTENUATED, 0.80, current.proposed_delta * 0.80, "GUARDIAN_NOISY_RECOVERY")
        return Decision(Verdict.PERMIT_FULL, 1.0, current.proposed_delta, "GUARDIAN_STABILIZING_PERMIT")

    # 3. Sigilith multi-signal risk: Headroom (H) + Directional Drift (D) + Uncertainty
    H = max(0.0, (current.coupled_load - 0.50) / (hard_bound - 0.50))
    window = [x.proposed_delta for x in history[-8:]] + [current.proposed_delta]
    D = abs(sum(window))
    drift_ratio = min(1.5, D / 0.24)
    uncertainty = min(1.0, (current.sensor_noise / 0.15) + (0.25 if current.packet_drop else 0.0))

    # Case D: Converged danger signal (low headroom + sustained directional push, or extreme perimeter proximity)
    if H >= 0.90 or (H >= 0.62 and drift_ratio >= 0.85):
        return Decision(Verdict.HOLD_ESCALATE, 0.0, 0.0, "SIGILITH_PERIMETER_ESCALATION")

    # Cases B & C: Smooth authority attenuation proportional to consumed margin
    if H >= 0.80:
        alpha = max(0.20, round(1.0 - (0.75 * H + 0.15 * min(1.0, drift_ratio) + 0.10 * uncertainty), 3))
        return Decision(Verdict.PERMIT_ATTENUATED, alpha, current.proposed_delta * alpha, f"GUARDIAN_DERATED_ALPHA_{alpha}")

    risk_score = (0.45 * H) + (0.40 * min(1.0, drift_ratio)) + (0.15 * uncertainty)
    if risk_score > 0.20:
        alpha = max(0.25, round(1.0 - risk_score, 3))
        return Decision(Verdict.PERMIT_ATTENUATED, alpha, current.proposed_delta * alpha, f"GUARDIAN_DERATED_ALPHA_{alpha}")

    return Decision(Verdict.PERMIT_FULL, 1.0, current.proposed_delta, "GUARDIAN_FULL_PERMIT")
