import math
import random
from typing import List, Tuple
from benchmarks.types import StepInput


def gen_regime_a_benign(rng: random.Random, steps: int = 60) -> Tuple[List[StepInput], int]:
    """Regime A: Benign volatility (surges, sensor jitter, temporary packet drops)."""
    seq, load = [], 0.45
    for t in range(steps):
        surge = 0.12 * math.sin(t / 6.0) + rng.gauss(0.0, 0.03)
        proposed = max(-0.20, min(0.20, surge))
        load = max(0.10, min(0.82, load + proposed * 0.35 - 0.12 * (load - 0.45)))
        seq.append(StepInput(
            step=t,
            proposed_delta=proposed,
            sensor_noise=abs(rng.gauss(0.0, 0.075)),
            packet_drop=(rng.random() < 0.08),
            corrupt_state=False,
            coupled_load=load,
        ))
    return seq, -1


def gen_regime_b_slow_drift(rng: random.Random, steps: int = 60) -> Tuple[List[StepInput], int]:
    """Regime B: Gradual parameter skew pushing coupled load toward the 1.0 cliff."""
    seq, load, onset = [], 0.50, 15
    for t in range(steps):
        bias = 0.022 if t >= onset else 0.0
        proposed = bias + rng.gauss(0.0, 0.01)
        load += proposed
        seq.append(StepInput(
            step=t,
            proposed_delta=proposed,
            sensor_noise=abs(rng.gauss(0.0, 0.02)),
            packet_drop=False,
            corrupt_state=False,
            coupled_load=load,
        ))
    return seq, onset


def gen_regime_c_adversarial(rng: random.Random, steps: int = 60) -> Tuple[List[StepInput], int]:
    """Regime C: Jitter-masked directional drift + state corruption injection."""
    seq, load, onset = [], 0.50, 10
    for t in range(steps):
        noise = 0.12 if 10 <= t <= 25 else 0.02
        bias = 0.035 if t >= 15 else 0.0
        proposed = bias + rng.gauss(0.0, 0.01)
        load += proposed
        seq.append(StepInput(
            step=t,
            proposed_delta=proposed,
            sensor_noise=noise,
            packet_drop=False,
            corrupt_state=(t == 32),
            coupled_load=load,
        ))
    return seq, onset
