#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
python scripts/build_manifest.py --check
export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"
export PYTHONDONTWRITEBYTECODE=1
export GUARDIAN_HMAC_SECRET="${GUARDIAN_HMAC_SECRET:-$(python -c 'import secrets; print(secrets.token_hex(32))')}"
export VERIFIER_HMAC_SECRET="${VERIFIER_HMAC_SECRET:-$(python -c 'import secrets; print(secrets.token_hex(32))')}"

python -m pytest -p no:cacheprovider -q

TMP_A="$(mktemp -d)"
TMP_B="$(mktemp -d)"
trap 'rm -rf "$TMP_A" "$TMP_B"' EXIT
(
  cd "$TMP_A"
  python "$ROOT/harnesses/ADV-003-A2.py"
)
B_OUTPUT="$(cd "$TMP_B" && python "$ROOT/harnesses/ADV-003-B-R1A.py" 2>&1)"
printf '%s\n' "$B_OUTPUT"
if ! grep -q 'VERDICT: PASS' <<<"$B_OUTPUT"; then
  echo 'RELEASE BLOCKED: ADV-003-B-R1A did not produce VERDICT: PASS.' >&2
  exit 1
fi
