"""Benchmark wrapper delegating directly to core.sigilith.SigilithAutonomyEngine."""

from __future__ import annotations

from benchmarks.types import Decision, StepInput, Verdict
from core.sigilith import SigilithAutonomyEngine

_ENGINE = SigilithAutonomyEngine()


def elastic_v2_controller(history: list[StepInput], current: StepInput) -> Decision:
    """Evaluate benchmark step using the production SigilithAutonomyEngine."""
    envelope = _ENGINE.evaluate(
        current_state=current.coupled_load,
        proposed_delta=current.proposed_delta,
        recent_deltas=[x.proposed_delta for x in history],
        sensor_noise=current.sensor_noise,
        packet_drop=current.packet_drop,
        corrupt_state=current.corrupt_state,
    )
    return Decision(
        verdict=Verdict(envelope.verdict.value),
        alpha=envelope.alpha,
        executed_delta=envelope.permitted_delta,
        reason=envelope.reason,
    )
