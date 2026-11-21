"""Single-node trajectory generators for Regimes A, B, and C."""

from __future__ import annotations

import math
import random

from benchmarks.types import StepInput

NOMINAL_LOAD = 0.45
BENIGN_CAP = 0.82
MEAN_REVERSION_RATE = 0.12
PACKET_DROP_PROB = 0.08


def gen_regime_a_benign(rng: random.Random, steps: int = 60) -> tuple[list[StepInput], int]:
    """Regime A: Benign volatility (load surges, sensor jitter, temporary packet drops)."""
    seq: list[StepInput] = []
    load = NOMINAL_LOAD
    for t in range(steps):
        surge = 0.12 * math.sin(t / 6.0) + rng.gauss(0.0, 0.03)
        proposed = max(-0.20, min(0.20, surge))
        load = max(0.10, min(BENIGN_CAP, load + proposed * 0.35 - MEAN_REVERSION_RATE * (load - NOMINAL_LOAD)))
        seq.append(
            StepInput(
                step=t,
                proposed_delta=proposed,
                sensor_noise=abs(rng.gauss(0.0, 0.075)),
                packet_drop=(rng.random() < PACKET_DROP_PROB),
                corrupt_state=False,
                coupled_load=load,
            )
        )
    return seq, -1


def gen_regime_b_slow_drift(rng: random.Random, steps: int = 60) -> tuple[list[StepInput], int]:
    """Regime B: Gradual parameter skew pushing coupled load toward the 1.0 cliff."""
    seq: list[StepInput] = []
    load = 0.50
    onset = 15
    for t in range(steps):
        bias = 0.022 if t >= onset else 0.0
        proposed = bias + rng.gauss(0.0, 0.01)
        load += proposed
        seq.append(
            StepInput(
                step=t,
                proposed_delta=proposed,
                sensor_noise=abs(rng.gauss(0.0, 0.02)),
                packet_drop=False,
                corrupt_state=False,
                coupled_load=load,
            )
        )
    return seq, onset


def gen_regime_c_adversarial(rng: random.Random, steps: int = 60) -> tuple[list[StepInput], int]:
    """Regime C: Jitter-masked directional drift followed by state corruption injection."""
    seq: list[StepInput] = []
    load = 0.50
    onset = 10
    for t in range(steps):
        noise = 0.12 if 10 <= t <= 25 else 0.02
        bias = 0.035 if t >= 15 else 0.0
        proposed = bias + rng.gauss(0.0, 0.01)
        load += proposed
        seq.append(
            StepInput(
                step=t,
                proposed_delta=proposed,
                sensor_noise=noise,
                packet_drop=False,
                corrupt_state=(t == 32),
                coupled_load=load,
            )
        )
    return seq, onset
