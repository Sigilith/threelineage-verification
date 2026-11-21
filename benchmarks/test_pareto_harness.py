"""Unit tests verifying determinism, invariant safety, and metric accuracy of the Pareto harness."""

from __future__ import annotations

import unittest

from benchmarks.controllers.binary_v1 import binary_v1_controller
from benchmarks.controllers.elastic_v2 import elastic_v2_controller
from benchmarks.pareto_harness import evaluate_suite
from benchmarks.regimes.coupled_grid import (
    gen_grid_regime_a_benign,
    gen_grid_regime_b_slow_drift,
    gen_grid_regime_c_adversarial,
)
from benchmarks.regimes.single_node import (
    gen_regime_a_benign,
    gen_regime_b_slow_drift,
    gen_regime_c_adversarial,
)


class TestParetoHarness(unittest.TestCase):
    """Regression and invariant tests for the Safety-Availability Pareto benchmark."""

    def test_deterministic_seed_reproducibility(self) -> None:
        regimes = {"A_Benign_Volatility": gen_regime_a_benign}
        run_one = evaluate_suite(elastic_v2_controller, regimes, n_runs=50, seed=2026)
        run_two = evaluate_suite(elastic_v2_controller, regimes, n_runs=50, seed=2026)
        self.assertEqual(run_one["A_Benign_Volatility"], run_two["A_Benign_Volatility"])

    def test_single_node_invariants_and_availability(self) -> None:
        regimes = {
            "A_Benign_Volatility": gen_regime_a_benign,
            "B_Slow_Drift": gen_regime_b_slow_drift,
            "C_Adversarial_Drift": gen_regime_c_adversarial,
        }
        bin_res = evaluate_suite(binary_v1_controller, regimes, n_runs=100, seed=2026)
        ela_res = evaluate_suite(elastic_v2_controller, regimes, n_runs=100, seed=2026)

        for name in regimes:
            self.assertEqual(ela_res[name].safety_violations, 0)

        self.assertEqual(ela_res["A_Benign_Volatility"].false_positive_trips, 0)
        self.assertEqual(ela_res["A_Benign_Volatility"].escalations, 0)

        bin_avail = bin_res["A_Benign_Volatility"].effective_availability
        ela_avail = ela_res["A_Benign_Volatility"].effective_availability
        self.assertIsNotNone(bin_avail)
        self.assertIsNotNone(ela_avail)
        assert bin_avail is not None and ela_avail is not None
        self.assertGreater(ela_avail, bin_avail)

        self.assertIsNone(ela_res["B_Slow_Drift"].effective_availability)
        self.assertIsNone(ela_res["C_Adversarial_Drift"].effective_availability)

    def test_coupled_grid_invariants(self) -> None:
        regimes = {
            "A_Benign_Volatility": gen_grid_regime_a_benign,
            "B_Slow_Drift": gen_grid_regime_b_slow_drift,
            "C_Adversarial_Drift": gen_grid_regime_c_adversarial,
        }
        ela_res = evaluate_suite(elastic_v2_controller, regimes, n_runs=100, seed=2026)
        for name in regimes:
            self.assertEqual(ela_res[name].safety_violations, 0)
        self.assertEqual(ela_res["A_Benign_Volatility"].false_positive_trips, 0)


if __name__ == "__main__":
    unittest.main()
