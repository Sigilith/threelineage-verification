"""Coupled 100-node ring topology generators for Regimes A, B, and C."""

from __future__ import annotations

import math
import random

from benchmarks.types import StepInput

DEFAULT_NODES = 100
PACKET_DROP_PROB = 0.08


def _init_nodes(rng: random.Random, n_nodes: int = DEFAULT_NODES, base: float = 0.45) -> list[float]:
    return [max(0.15, min(0.75, base + rng.gauss(0.0, 0.04))) for _ in range(n_nodes)]


def gen_grid_regime_a_benign(
    rng: random.Random, steps: int = 60, n_nodes: int = DEFAULT_NODES
) -> tuple[list[StepInput], int]:
    """100-node Regime A: Local feeder surges with telemetry jitter and packet drops."""
    nodes = _init_nodes(rng, n_nodes, 0.45)
    seq: list[StepInput] = []
    for t in range(steps):
        proposed = max(-0.18, min(0.18, 0.11 * math.sin(t / 5.5) + rng.gauss(0.0, 0.025)))
        seq.append(
            StepInput(
                step=t,
                proposed_delta=proposed,
                sensor_noise=abs(rng.gauss(0.0, 0.075)),
                packet_drop=(rng.random() < PACKET_DROP_PROB),
                corrupt_state=False,
                coupled_load=max(nodes),
                node_loads=list(nodes),
            )
        )
    return seq, -1


def gen_grid_regime_b_slow_drift(
    rng: random.Random, steps: int = 60, n_nodes: int = DEFAULT_NODES
) -> tuple[list[StepInput], int]:
    """100-node Regime B: Correlated cluster skew driving regional cascade pressure."""
    nodes = _init_nodes(rng, n_nodes, 0.48)
    seq: list[StepInput] = []
    onset = 15
    for t in range(steps):
        bias = 0.024 if t >= onset else 0.0
        proposed = bias + rng.gauss(0.0, 0.008)
        seq.append(
            StepInput(
                step=t,
                proposed_delta=proposed,
                sensor_noise=abs(rng.gauss(0.0, 0.02)),
                packet_drop=False,
                corrupt_state=False,
                coupled_load=max(nodes),
                node_loads=list(nodes),
            )
        )
    return seq, onset


def gen_grid_regime_c_adversarial(
    rng: random.Random, steps: int = 60, n_nodes: int = DEFAULT_NODES
) -> tuple[list[StepInput], int]:
    """100-node Regime C: Coordinated multi-node ramp masked by jitter and state tamper."""
    nodes = _init_nodes(rng, n_nodes, 0.48)
    seq: list[StepInput] = []
    onset = 10
    for t in range(steps):
        noise = 0.12 if 10 <= t <= 25 else 0.02
        bias = 0.038 if t >= 15 else 0.0
        proposed = bias + rng.gauss(0.0, 0.008)
        seq.append(
            StepInput(
                step=t,
                proposed_delta=proposed,
                sensor_noise=noise,
                packet_drop=False,
                corrupt_state=(t == 32),
                coupled_load=max(nodes),
                node_loads=list(nodes),
            )
        )
    return seq, onset
