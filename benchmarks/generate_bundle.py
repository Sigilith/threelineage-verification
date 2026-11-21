from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import platform
import subprocess

FENCE = chr(96) * 3


def run(cmd):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True).strip()
    except Exception:
        return "unavailable"


def main():
    repo_root = Path.cwd()
    artifact = Path("benchmarks/results/pareto_benchmark_20261121T053243Z.json")
    sha_file = Path("benchmarks/results/pareto_benchmark_20261121T053243Z.sha256")
    deps_file = Path("benchmarks/results/dependencies.txt")

    raw_bytes = artifact.read_bytes()
    actual_sha = hashlib.sha256(raw_bytes).hexdigest()
    expected_sha = sha_file.read_text(encoding="utf-8").split()[0]
    verified = actual_sha == expected_sha

    mem_total = "unavailable"
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemTotal:"):
                kb = int(line.split()[1])
                mem_total = f"{kb / (1024 * 1024):.2f} GiB"
                break
    except Exception:
        pass

    commit_hash = run(["git", "rev-parse", "HEAD"])
    remote_url = run(["git", "remote", "get-url", "origin"])
    branch_name = run(["git", "branch", "--show-current"])
    tree_status = run(["git", "status", "--porcelain"]) or "clean"
    created_utc = datetime.fromtimestamp(artifact.stat().st_mtime, tz=timezone.utc).isoformat()
    deps_sha = hashlib.sha256(deps_file.read_bytes()).hexdigest()

    lines = [
        "# Minimum Evidence Bundle — `pareto_benchmark_20261121T053243Z`",
        "",
        "## 1. Repository Integrity",
        f"- **Repository:** `{repo_root.name}`",
        f"- **Remote:** `{remote_url}`",
        f"- **Branch:** `{branch_name}`",
        f"- **Commit:** `{commit_hash}`",
        f"- **Working Tree Status:** `{tree_status}`",
        "",
        "## 2. Benchmark Configuration",
        "- **Harness:** `benchmarks/pareto_harness.py` (v1.0)",
        "- **Profiles:** `Single_Node`, `Coupled_100_Node_Grid`",
        "- **Regimes:** `A_Benign_Volatility`, `B_Slow_Drift`, `C_Adversarial_Drift`",
        "- **Trials per Regime:** `10,000` (`60,000` total trajectories)",
        "- **Random Seed:** `2026`",
        "- **Models Evaluated:** `Binary_V1`, `Elastic_V2`",
        "",
        "## 3. Platform Metadata",
        f"- **OS:** `{platform.system()} {platform.release()} ({platform.machine()})`",
        f"- **Kernel:** `{run(['uname', '-r'])}`",
        f"- **CPU Cores:** `{os.cpu_count()}`",
        f"- **RAM Capacity:** `{mem_total}`",
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
        f"{FENCE}bash",
        "git clone https://github.com/Sigilith/threelineage-verification.git",
        "cd threelineage-verification",
        f"git checkout {commit_hash}",
        "python -m benchmarks.pareto_harness --runs 10000 --seed 2026 --profile both",
        FENCE,
        "",
        "## 6. Publication Verification Statement",
        "All benchmark results were generated from version-controlled source code using a documented execution environment, fixed scenario definitions, recorded random seeds, and cryptographically hashed output artifacts. Results demonstrate behaviour within the tested benchmark environment only and should not be interpreted as certification, regulatory approval, or evidence of production deployment suitability.",
        "",
    ]

    out = Path("benchmarks/results/evidence_bundle_20261121T053243Z.md")
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"Wrote {out} (SHA-256 verified: {verified})")


if __name__ == "__main__":
    main()
