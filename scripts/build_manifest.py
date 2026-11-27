#!/usr/bin/env python3
"""Create or verify the SHA-256 manifest for this release package."""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "manifest.json"
MANIFEST_SHA = ROOT / "manifest.sha256"
EXCLUDED_DIRS = {".git", "__pycache__", ".pytest_cache"}
FORBIDDEN_SUFFIXES = {".pyc", ".pyo", ".bak", ".swp"}
BASELINE_SHA256 = "32a9c5f8746d9416ea9184f417b479d206f012e37d46b91b1bc6b2ca77708011"


def inventory():
    entries = []
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file() or path in {MANIFEST, MANIFEST_SHA}:
            continue
        rel = path.relative_to(ROOT)
        if ".git" in rel.parts:
            continue
        if any(part in EXCLUDED_DIRS - {".git"} for part in rel.parts):
            raise SystemExit(f"Forbidden generated directory in package: {rel}")
        if path.suffix in FORBIDDEN_SUFFIXES or path.name in {".env", ".env.local"}:
            raise SystemExit(f"Forbidden generated/secret file in package: {rel}")
        data = path.read_bytes()
        entries.append({"path": rel.as_posix(), "size_bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    return {
        "release": "ThreeLineage-V1.1.0-candidate",
        "manifest_format": 1,
        "hash_algorithm": "SHA-256",
        "frozen_rc2_1_handover_archive_sha256": BASELINE_SHA256,
        "files": entries,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = inventory()
    rendered = json.dumps(expected, indent=2, sort_keys=True) + "\n"
    expected_sha = hashlib.sha256(rendered.encode("utf-8")).hexdigest() + "  manifest.json\n"
    if args.check:
        if not MANIFEST.exists():
            raise SystemExit("Manifest missing; regenerate with python scripts/build_manifest.py")
        current_text = MANIFEST.read_text(encoding="utf-8")
        if current_text != rendered:
            current_obj = json.loads(current_text)
            expected_by_path = {entry["path"]: entry for entry in expected["files"]}
            current_by_path = {entry["path"]: entry for entry in current_obj.get("files", [])}
            missing = sorted(set(expected_by_path) - set(current_by_path))
            extra = sorted(set(current_by_path) - set(expected_by_path))
            changed = sorted(path for path in set(expected_by_path) & set(current_by_path)
                             if expected_by_path[path] != current_by_path[path])
            print(json.dumps({"expected_entries": len(expected_by_path), "manifest_entries": len(current_by_path),
                              "missing_from_manifest": missing, "extra_in_manifest": extra,
                              "changed_entries": changed}, indent=2))
            raise SystemExit("Manifest mismatch; regenerate with python scripts/build_manifest.py")
        if not MANIFEST_SHA.exists() or MANIFEST_SHA.read_text(encoding="utf-8") != expected_sha:
            print(f"Expected manifest SHA-256: {expected_sha.strip()}")
            current_sha = MANIFEST_SHA.read_text(encoding="utf-8").strip() if MANIFEST_SHA.exists() else "<missing>"
            print(f"Current manifest SHA-256: {current_sha}")
            raise SystemExit("Manifest SHA-256 mismatch; regenerate with python scripts/build_manifest.py")
        print(f"Manifest verified: {len(expected['files'])} files; SHA-256 sidecar verified")
    else:
        MANIFEST.write_text(rendered, encoding="utf-8")
        MANIFEST_SHA.write_text(expected_sha, encoding="utf-8")
        print(f"Manifest written: {len(expected['files'])} files")


if __name__ == "__main__":
    main()
