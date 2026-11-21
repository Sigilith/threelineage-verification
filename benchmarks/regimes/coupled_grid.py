import math
import random
from typing import List, Tuple
from benchmarks.types import StepInput


def _init_nodes(rng: random.Random, n_nodes: int = 100, base: float = 0.45) -> List[float]:
    return [max(0.15, min(0.75, base + rng.gauss(0.0, 0.04))) for _ in range(n_nodes)]


def gen_grid_regime_a_benign(rng: random.Random, steps: int = 60, n_nodes: int = 100) -> Tuple[List[StepInput], int]:
    """100-node Regime A: Local feeder load surges + telemetry jitter/drops."""
    nodes = _init_nodes(rng, n_nodes, 0.45)
    seq = []
    for t in range(steps):
        proposed = max(-0.18, min(0.18, 0.11 * math.sin(t / 5.5) + rng.gauss(0.0, 0.025)))
        seq.append(StepInput(
            step=t,
            proposed_delta=proposed,
            sensor_noise=abs(rng.gauss(0.0, 0.075)),
            packet_drop=(rng.random() < 0.08),
            corrupt_state=False,
            coupled_load=max(nodes),
            node_loads=list(nodes),
        ))
    return seq, -1


def gen_grid_regime_b_slow_drift(rng: random.Random, steps: int = 60, n_nodes: int = 100) -> Tuple[List[StepInput], int]:
    """100-node Regime B: Correlated cluster skew driving regional cascade risk."""
    nodes = _init_nodes(rng, n_nodes, 0.48)
    seq, onset = [], 15
    for t in range(steps):
        bias = 0.024 if t >= onset else 0.0
        proposed = bias + rng.gauss(0.0, 0.008)
        seq.append(StepInput(
            step=t,
            proposed_delta=proposed,
            sensor_noise=abs(rng.gauss(0.0, 0.02)),
            packet_drop=False,
            corrupt_state=False,
            coupled_load=max(nodes),
            node_loads=list(nodes),
        ))
    return seq, onset


def gen_grid_regime_c_adversarial(rng: random.Random, steps: int = 60, n_nodes: int = 100) -> Tuple[List[StepInput], int]:
    """100-node Regime C: Coordinated multi-node ramp masked by jitter + state tamper."""
    nodes = _init_nodes(rng, n_nodes, 0.48)
    seq, onset = [], 10
    for t in range(steps):
        noise = 0.12 if 10 <= t <= 25 else 0.02
        bias = 0.038 if t >= 15 else 0.0
        proposed = bias + rng.gauss(0.0, 0.008)
        seq.append(StepInput(
            step=t,
            proposed_delta=proposed,
            sensor_noise=noise,
            packet_drop=False,
            corrupt_state=(t == 32),
            coupled_load=max(nodes),
            node_loads=list(nodes),
        ))
    return seq, onset
