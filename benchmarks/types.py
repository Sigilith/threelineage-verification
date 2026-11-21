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

    hard_invariant_violations: int = 0
    constraint_escapes: int = 0
    false_positive_trips: int = 0
    total_evaluated_steps: int = 0
    permit_full_steps: int = 0
    attenuated_steps: int = 0
    escalations: int = 0
    fail_closed_trips: int = 0
    elapsed_seconds: float = 0.0
    requested_benign_work: float = 0.0
    completed_benign_work: float = 0.0
    trial_completion_rates: list[float] = field(default_factory=list)
    intervention_delays: list[int] = field(default_factory=list)

    @property
    def safety_violations(self) -> int:
        """Combined hard invariant violations and constraint escapes."""
        return self.hard_invariant_violations + self.constraint_escapes

    @property
    def effective_availability(self) -> float | None:
        """Aggregate ratio of completed to requested benign work."""
        if self.requested_benign_work == 0.0:
            return None
        return self.completed_benign_work / self.requested_benign_work

    @property
    def mean_task_completion_rate(self) -> float | None:
        """Mean per-trial task completion ratio across benign runs."""
        if not self.trial_completion_rates:
            return None
        return sum(self.trial_completion_rates) / len(self.trial_completion_rates)

    @property
    def permit_throughput_pct(self) -> float:
        """Percentage of evaluated steps granted full or attenuated execution permits."""
        if self.total_evaluated_steps == 0:
            return 0.0
        return ((self.permit_full_steps + self.attenuated_steps) / self.total_evaluated_steps) * 100.0

    @property
    def permits_per_sec(self) -> float:
        """Wall-clock permitted decisions executed per second."""
        if self.elapsed_seconds <= 0.0:
            return 0.0
        return (self.permit_full_steps + self.attenuated_steps) / self.elapsed_seconds
