#!/usr/bin/env python3
"""Generate a verified Minimum Evidence Bundle Markdown report for a benchmark artifact."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess


def run_cmd(cmd: list[str]) -> str:
    """Execute a subprocess command and return stripped stdout, or 'unavailable'."""
    try:
        return subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True).strip()
    except Exception:
        return "unavailable"


def get_mem_total() -> str:
    """Read total physical RAM from /proc/meminfo when available."""
    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            if line.startswith("MemTotal:"):
                kb = int(line.split()[1])
                return f"{kb / (1024 * 1024):.2f} GiB"
    except Exception:
        pass
    return "unavailable"


def resolve_artifact(explicit_path: str | None) -> Path:
    """Resolve explicit artifact path or select the most recent JSON artifact."""
    if explicit_path:
        return Path(explicit_path)
    candidates = sorted(Path("benchmarks/results").glob("pareto_benchmark_*.json"))
    if not candidates:
        raise FileNotFoundError("No pareto_benchmark_*.json artifacts found in benchmarks/results/")
    return candidates[-1]


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate Minimum Evidence Bundle Markdown")
    parser.add_argument("--artifact", type=str, default=None, help="Path to pareto_benchmark_*.json")
    args = parser.parse_args()

    artifact = resolve_artifact(args.artifact)
    sha_file = artifact.with_suffix(".sha256")
    deps_file = Path("benchmarks/results/dependencies.txt")

    raw_bytes = artifact.read_bytes()
    actual_sha = hashlib.sha256(raw_bytes).hexdigest()
    expected_sha = sha_file.read_text(encoding="utf-8").split()[0]
    verified = actual_sha == expected_sha

    meta = json.loads(raw_bytes.decode("utf-8"))
    runs = meta.get("runs_per_regime", "unknown")
    seed = meta.get("seed", "unknown")
    harness_ver = meta.get("harness_version", "1.0.0")
    profiles_list = ", ".join(f"`{p}`" for p in meta.get("profiles", {}).keys())

    commit_hash = run_cmd(["git", "rev-parse", "HEAD"])
    remote_url = run_cmd(["git", "remote", "get-url", "origin"])
    branch_name = run_cmd(["git", "branch", "--show-current"])
    tree_status = run_cmd(["git", "status", "--porcelain"]) or "clean"
    created_utc = datetime.fromtimestamp(artifact.stat().st_mtime, tz=timezone.utc).isoformat()
    deps_sha = hashlib.sha256(deps_file.read_bytes()).hexdigest() if deps_file.exists() else "unavailable"

    fence = "```"
    bundle = "\n".join(
        [
            f"# Minimum Evidence Bundle — `{artifact.stem}`",
            "",
            "## 1. Repository Integrity",
            f"- **Repository:** `{Path.cwd().name}`",
            f"- **Remote:** `{remote_url}`",
            f"- **Branch:** `{branch_name}`",
            f"- **Commit:** `{commit_hash}`",
            f"- **Working Tree Status:** `{tree_status}`",
            "",
            "## 2. Benchmark Configuration",
            f"- **Harness:** `benchmarks/pareto_harness.py` (v{harness_ver})",
            f"- **Profiles:** {profiles_list}",
            "- **Regimes:** `A_Benign_Volatility`, `B_Slow_Drift`, `C_Adversarial_Drift`",
            f"- **Trials per Regime:** `{runs:,}`" if isinstance(runs, int) else f"- **Trials per Regime:** `{runs}`",
            f"- **Random Seed:** `{seed}`",
            "- **Models Evaluated:** `Binary_V1`, `Elastic_V2`",
            "",
            "## 3. Platform Metadata",
            f"- **OS:** `{platform.system()} {platform.release()} ({platform.machine()})`",
            f"- **Kernel:** `{run_cmd(['uname', '-r'])}`",
            f"- **CPU Cores:** `{os.cpu_count()}`",
            f"- **RAM Capacity:** `{get_mem_total()}`",
            f"- **Python Version:** `{platform.python_version()}`",
            "",
            "## 4. Artifact & Dependency Integrity",
            f"- **Result File:** `{artifact}`",
            f"- **Artifact Size:** `{artifact.stat().st_size} bytes`",
            f"- **Creation Time (UTC):** `{created_utc}`",
            f"- **SHA-256:** `{actual_sha}`",
            f"- **SHA-256 Verified:** `{'PASS' if verified else 'FAIL'}`",
            f"- **Dependency Manifest:** `{deps_file}` (SHA-256: `{deps_sha}`)",
            "",
            "## 5. Reproduction Command",
            f"{fence}bash",
            "git clone [https://github.com/Sigilith/threelineage-verification.git](https://github.com/Sigilith/threelineage-verification.git)",
            "cd threelineage-verification",
            f"git checkout {commit_hash}",
            f"python -m benchmarks.pareto_harness --runs {runs} --seed {seed} --profile both",
            fence,
            "",
            "## 6. Publication Verification Statement",
            (
                "All benchmark results were generated from version-controlled source code using a documented "
                "execution environment, fixed scenario definitions, recorded random seeds, and cryptographically "
                "hashed output artifacts. Results demonstrate behaviour within the tested benchmark environment "
                "only and should not be interpreted as certification, regulatory approval, or evidence of "
                "production deployment suitability."
            ),
            "",
        ]
    )

    out_path = artifact.with_name(f"evidence_bundle_{artifact.stem.removeprefix('pareto_benchmark_')}.md")
    out_path.write_text(bundle, encoding="utf-8")
    print(f"Wrote {out_path} (SHA-256 verified: {verified})")


if __name__ == "__main__":
    main()
