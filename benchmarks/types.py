from dataclasses import dataclass, field
from enum import Enum
from typing import List


class Verdict(str, Enum):
    PERMIT_FULL = "PERMIT_FULL"
    PERMIT_ATTENUATED = "PERMIT_ATTENUATED"
    HOLD_ESCALATE = "HOLD_ESCALATE"
    FAIL_CLOSED = "FAIL_CLOSED"


@dataclass
class StepInput:
    step: int
    proposed_delta: float
    sensor_noise: float
    packet_drop: bool
    corrupt_state: bool
    coupled_load: float
    node_loads: List[float] = field(default_factory=list)


@dataclass
class Decision:
    verdict: Verdict
    alpha: float
    executed_delta: float
    reason: str = ""


@dataclass
class RunMetrics:
    safety_violations: int = 0
    false_positive_trips: int = 0
    escalations: int = 0
    attenuated_steps: int = 0
    requested_benign_work: float = 0.0
    completed_benign_work: float = 0.0
    intervention_delays: List[int] = field(default_factory=list)

    @property
    def effective_availability(self) -> float:
        if self.requested_benign_work == 0.0:
            return 1.0
        return self.completed_benign_work / self.requested_benign_work
