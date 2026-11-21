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
TMP_C="$(mktemp -d)"
trap 'rm -rf "$TMP_A" "$TMP_B" "$TMP_C"' EXIT

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

C_OUTPUT="$(cd "$TMP_C" && python "$ROOT/harnesses/ADV-004-ELASTIC-PIPELINE.py" 2>&1)"
printf '%s\n' "$C_OUTPUT"
if ! grep -q 'VERDICT: PASS' <<<"$C_OUTPUT"; then
  echo 'RELEASE BLOCKED: ADV-004-ELASTIC-PIPELINE did not produce VERDICT: PASS.' >&2
  exit 1
fi

TMP_D="$(mktemp -d)"
trap 'rm -rf "$TMP_A" "$TMP_B" "$TMP_C" "$TMP_D"' EXIT
D_OUTPUT="$(cd "$TMP_D" && python "$ROOT/harnesses/ADV-005-DELEGATION-CHAIN.py" 2>&1)"
printf '%s\n' "$D_OUTPUT"
if ! grep -q 'VERDICT: PASS' <<<"$D_OUTPUT"; then
  echo 'RELEASE BLOCKED: ADV-005-DELEGATION-CHAIN did not produce VERDICT: PASS.' >&2
  exit 1
fi
