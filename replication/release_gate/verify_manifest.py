#!/usr/bin/env python3
"""Verify clean-room files against manifest.json and manifest.sha256."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys


def verify_tree(root: Path, manifest_path: Path, sha_sidecar_path: Path) -> dict[str, object]:
    if not manifest_path.exists():
        raise FileNotFoundError(f"Missing manifest: {manifest_path}")
    if not sha_sidecar_path.exists():
        raise FileNotFoundError(f"Missing manifest SHA-256 sidecar: {sha_sidecar_path}")

    manifest_bytes = manifest_path.read_bytes()
    actual_manifest_sha = hashlib.sha256(manifest_bytes).hexdigest()
    sidecar_text = sha_sidecar_path.read_text(encoding="utf-8").strip()
    expected_manifest_sha = sidecar_text.split()[0] if sidecar_text else ""

    if actual_manifest_sha != expected_manifest_sha:
        raise ValueError(
            f"Manifest sidecar SHA-256 mismatch: expected {expected_manifest_sha}, got {actual_manifest_sha}"
        )

    manifest_obj = json.loads(manifest_bytes.decode("utf-8"))
    files = manifest_obj.get("files")
    if not isinstance(files, list):
        raise ValueError("Invalid manifest structure: 'files' must be a list")

    mismatches: list[dict[str, str]] = []
    for entry in files:
        rel_path = entry["path"]
        expected_sha = entry["sha256"]
        target = root / rel_path
        if not target.is_file():
            mismatches.append({"path": rel_path, "reason": "missing_file"})
            continue
        actual_sha = hashlib.sha256(target.read_bytes()).hexdigest()
        if actual_sha != expected_sha:
            mismatches.append({
                "path": rel_path,
                "reason": "sha256_mismatch",
                "expected": expected_sha,
                "actual": actual_sha,
            })

    return {
        "verified": len(mismatches) == 0,
        "checked_entries": len(files),
        "manifest_sha256": actual_manifest_sha,
        "mismatches": mismatches,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify repository files against manifest.json and manifest.sha256.")
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output-json", type=Path)
    args = parser.parse_args()

    result = verify_tree(
        root=args.root.resolve(),
        manifest_path=args.root.resolve() / "manifest.json",
        sha_sidecar_path=args.root.resolve() / "manifest.sha256",
    )
    if args.output_json:
        args.output_json.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["verified"] else 1


if __name__ == "__main__":
    sys.exit(main())
