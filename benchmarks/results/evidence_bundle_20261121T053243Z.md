# Minimum Evidence Bundle — `pareto_benchmark_20261121T053243Z`

## 1. Repository Integrity
- **Repository:** `threelineage-verification`
- **Remote:** `https://github.com/Sigilith/threelineage-verification.git`
- **Branch:** `feat/pareto-benchmark`
- **Commit:** `7d16410bba220905afabf2d6bc6b666a52e1a820`
- **Working Tree Status:** `clean`

## 2. Benchmark Configuration
- **Harness:** `benchmarks/pareto_harness.py` (v1.0.0)
- **Profiles:** `Single_Node`, `Coupled_100_Node_Grid`
- **Regimes:** `A_Benign_Volatility`, `B_Slow_Drift`, `C_Adversarial_Drift`
- **Trials per Regime:** `10,000`
- **Random Seed:** `2026`
- **Models Evaluated:** `Binary_V1`, `Elastic_V2`

## 3. Platform Metadata
- **OS:** `Android 15 (aarch64)`
- **Kernel:** `5.4.274-qgki-30959342-abF711BXXSJJZH3`
- **CPU Cores:** `8`
- **RAM Capacity:** `7.22 GiB`
- **Python Version:** `3.13.13`

## 4. Artifact & Dependency Integrity
- **Result File:** `benchmarks/results/pareto_benchmark_20261121T053243Z.json`
- **Artifact Size:** `3574 bytes`
- **Creation Time (UTC):** `2026-11-21T05:32:43.365958+00:00`
- **SHA-256:** `a4afc16ed80f093016aaa11bd85de3d74676e42c505ad99032b9ab682c7d423c`
- **SHA-256 Verified:** `PASS`
- **Dependency Manifest:** `benchmarks/results/dependencies.txt` (SHA-256: `506ee1b0701ec45a78e8c6b5a9027fe049114339201424a85636e228c4178359`)

## 5. Reproduction Command
```bash
git clone [https://github.com/Sigilith/threelineage-verification.git](https://github.com/Sigilith/threelineage-verification.git)
cd threelineage-verification
git checkout 7d16410bba220905afabf2d6bc6b666a52e1a820
python -m benchmarks.pareto_harness --runs 10000 --seed 2026 --profile both
```

## 6. Publication Verification Statement
All benchmark results were generated from version-controlled source code using a documented execution environment, fixed scenario definitions, recorded random seeds, and cryptographically hashed output artifacts. Results demonstrate behaviour within the tested benchmark environment only and should not be interpreted as certification, regulatory approval, or evidence of production deployment suitability.
