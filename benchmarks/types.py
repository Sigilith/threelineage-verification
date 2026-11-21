"""Core data structures for the ThreeLineage Safety-Availability Pareto benchmark."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Verdict(str, Enum):
    """Runtime governance decision tiers."""

    PERMIT_FULL = "PERMIT_FULL"
    PERMIT_ATTENUATED = "PERMIT_ATTENUATED"
    HOLD_ESCALATE = "HOLD_ESCALATE"
    FAIL_CLOSED = "FAIL_CLOSED"


@dataclass
class StepInput:
    """Single simulation timestep state and proposed action."""

    step: int
    proposed_delta: float
    sensor_noise: float
    packet_drop: bool
    corrupt_state: bool
    coupled_load: float
    node_loads: list[float] = field(default_factory=list)


@dataclass
class Decision:
    """Controller verdict and permitted actuation magnitude."""

    verdict: Verdict
    alpha: float
    executed_delta: float
    reason: str = ""


@dataclass
class RunMetrics:
    """Aggregated safety, availability, governance, and timing metrics."""

    safety_violations: int = 0
    false_positive_trips: int = 0
    permit_full_steps: int = 0
    attenuated_steps: int = 0
    escalations: int = 0
    fail_closed_trips: int = 0
    requested_benign_work: float = 0.0
    completed_benign_work: float = 0.0
    intervention_delays: list[int] = field(default_factory=list)

    @property
    def effective_availability(self) -> float | None:
        """Ratio of completed to requested benign work (None for non-benign regimes)."""
        if self.requested_benign_work == 0.0:
            return None
        return self.completed_benign_work / self.requested_benign_work
