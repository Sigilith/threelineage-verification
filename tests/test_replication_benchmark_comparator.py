"""Regression tests for the independent v1.2.0 benchmark comparator."""

import importlib.util
from pathlib import Path
import unittest

MODULE_PATH = Path(__file__).resolve().parents[1] / "replication" / "benchmark" / "run_v1_2_0.py"
SPEC = importlib.util.spec_from_file_location("run_v1_2_0", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


class BenchmarkComparatorTests(unittest.TestCase):
    def _payload(self, availability):
        return {
            "profiles": {
                "Single_Node": {
                    "Elastic_V2": {
                        "A_Benign_Volatility": {
                            "safety_metrics": {"fail_closed_activations": 0},
                            "availability_metrics": availability,
                        }
                    }
                }
            }
        }

    def test_reads_throughput_from_nested_availability_metrics(self):
        extracted = MODULE._extract_metrics(
            self._payload({"permit_throughput_pct": 100.0})
        )
        self.assertEqual(extracted["benign_elastic_rows"], 1)
        self.assertEqual(extracted["benign_elastic_permit_throughput_pct"], [100.0])
        self.assertEqual(extracted["benign_elastic_missing_throughput"], 0)

    def test_missing_throughput_is_counted_as_missing(self):
        extracted = MODULE._extract_metrics(self._payload({}))
        self.assertEqual(extracted["benign_elastic_rows"], 1)
        self.assertEqual(extracted["benign_elastic_permit_throughput_pct"], [])
        self.assertEqual(extracted["benign_elastic_missing_throughput"], 1)

    def test_missing_fail_closed_metric_is_counted_as_missing(self):
        payload = self._payload({"permit_throughput_pct": 100.0})
        del payload["profiles"]["Single_Node"]["Elastic_V2"]["A_Benign_Volatility"]["safety_metrics"]["fail_closed_activations"]
        extracted = MODULE._extract_metrics(payload)
        self.assertEqual(extracted["benign_elastic_missing_fail_closed_trips"], 1)


if __name__ == "__main__":
    unittest.main()
