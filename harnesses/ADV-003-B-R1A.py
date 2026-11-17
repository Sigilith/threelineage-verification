#!/usr/bin/env python3
"""
ADV-003-B-R1A Test Harness: Historical Nonce Substitution Tampering
Target Component: ReplayProtectedHeartbeatVerifier (TraceGuard)
Compliance: ER-001, ER-002, ER-003, ER-005 (Persistent Tamper Rejection)
Authoritative Standard: THREELINEAGE FORMAL SECURITY INVARIANTS & THREAT MODEL v1.0
"""

import os
import sys
import json
import hashlib
import time
import inspect
import argparse
import subprocess
from pathlib import Path

ARTEFACT_DIR = Path("ADV-003-B-R1A")
ARTEFACT_DIR.mkdir(exist_ok=True)
RESOURCE_FILE = ARTEFACT_DIR / "resource_state.json"

class MockPublicKey:
    def verify(self, sig_bytes, canonical_data):
        pass  # Accept all signatures in test harness

def sha256_file(filepath):
    h = hashlib.sha256()
    path = Path(filepath)
    if not path.exists():
        return "MISSING"
    with open(path, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()

def record_artifact(name, data):
    path = ARTEFACT_DIR / name
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    return path

def get_resource_mutation_count():
    if not RESOURCE_FILE.exists():
        return 0
    try:
        with open(RESOURCE_FILE, "r") as f:
            return json.load(f).get("mutation_count", 0)
    except Exception:
        return 0

def increment_resource_mutation():
    current = get_resource_mutation_count()
    with open(RESOURCE_FILE, "w") as f:
        json.dump({"mutation_count": current + 1, "timestamp": time.time()}, f, indent=2)

def instantiate_verifier(state_file_path):
    from core.telemetry_verifier import ReplayProtectedHeartbeatVerifier
    registry = {"node_001": MockPublicKey()}
    return ReplayProtectedHeartbeatVerifier(
        node_key_registry=registry,
        state_file_path=state_file_path,
        max_drift_seconds=86400.0
    )

# =====================================================================
# WORKER MODE (Executed in separate OS process G1 / G2)
# =====================================================================
if len(sys.argv) > 1 and sys.argv[1] == "--worker":
    parser = argparse.ArgumentParser()
    parser.add_argument("--worker", action="store_true")
    parser.add_argument("--state-file", required=True)
    parser.add_argument("--action", choices=["commit", "verify_load", "probe_replay"], default="verify_load")
    parser.add_argument("--node-id", default="node_001")
    parser.add_argument("--nonce", default="nonce_r0")
    args = parser.parse_args(sys.argv[1:])

    try:
        if args.action == "commit":
            verifier = instantiate_verifier(args.state_file)
            packet = {
                "node_id": args.node_id,
                "timestamp": time.time(),
                "nonce": args.nonce,
                "payload": {"seq": 0, "val": "genesis"},
                "signature": "00" * 64
            }
            success = verifier.verify_and_accept(packet)
            evidence = {
                "action": "commit",
                "pid": os.getpid(),
                "success": success,
                "nonce": args.nonce
            }
            print(json.dumps(evidence))
            sys.exit(0 if success else 1)

        elif args.action == "verify_load":
            # Instantiating verifier triggers _load_persistent_state()
            load_error = None
            loaded_nonces = []
            try:
                verifier = instantiate_verifier(args.state_file)
                # Extract loaded nonces from verifier internal state for telemetry inspection
                loaded_nonces = [k[1] for k in verifier.seen_nonces.keys()]
            except Exception as ex:
                load_error = str(ex)

            evidence = {
                "action": "verify_load",
                "pid": os.getpid(),
                "load_success": load_error is None,
                "load_error": load_error,
                "loaded_nonces": loaded_nonces
            }
            print(json.dumps(evidence))
            sys.exit(0 if load_error is None else 1)

        elif args.action == "probe_replay":
            # Test whether the ORIGINAL nonce (nonce_r0) can now be replayed
            # after its historical record was substituted with nonce_forged in the state file.
            verifier = instantiate_verifier(args.state_file)
            packet = {
                "node_id": args.node_id,
                "timestamp": time.time(),
                "nonce": args.nonce,  # Probing original nonce_r0
                "payload": {"seq": 0, "val": "replay_attempt"},
                "signature": "00" * 64
            }
            allowed = verifier.verify_and_accept(packet)
            evidence = {
                "action": "probe_replay",
                "pid": os.getpid(),
                "probed_nonce": args.nonce,
                "replay_allowed": allowed,  # True = Replay succeeded (security flaw if it was supposed to be consumed)
                "reason": "REPLAY_ACCEPTED" if allowed else "REPLAY_REJECTED"
            }
            print(json.dumps(evidence))
            sys.exit(0)

    except Exception as e:
        err_evidence = {
            "pid": os.getpid(),
            "error": str(e)
        }
        print(json.dumps(err_evidence))
        sys.exit(2)

# =====================================================================
# PARENT HARNESS MODE (ADV-003-B-R1A Controller)
# =====================================================================
def run_worker(state_file, action, nonce="nonce_r0"):
    cmd = [
        sys.executable, __file__, "--worker",
        "--state-file", state_file,
        "--action", action,
        "--nonce", nonce
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    output_lines = res.stdout.strip().splitlines()
    json_payload = {}
    for line in output_lines:
        try:
            json_payload = json.loads(line)
            break
        except Exception:
            continue

    return {
        "returncode": res.returncode,
        "stdout": res.stdout.strip(),
        "stderr": res.stderr.strip(),
        "structured_evidence": json_payload
    }

def run_adv_003_b_r1a():
    print("=== ADV-003-B-R1A: Historical Nonce Substitution Tampering ===")

    # ---------------------------------------------------------
    # STAGE 0: Baseline & State File Initialisation
    # ---------------------------------------------------------
    print("[*] Stage 0: Initialising pristine TraceGuard telemetry state file...")
    with open(RESOURCE_FILE, "w") as f:
        json.dump({"mutation_count": 0, "timestamp": time.time()}, f, indent=2)

    state_file = str(ARTEFACT_DIR / "r1a_telemetry.state")
    if Path(state_file).exists():
        Path(state_file).unlink()

    stage0_record = {
        "test_id": "ADV-003-B-R1A",
        "timestamp": time.time(),
        "state_file_path": state_file,
        "parent_pid": os.getpid()
    }
    record_artifact("stage0_baseline.json", stage0_record)

    # ---------------------------------------------------------
    # STAGE 1: Commit Legitimate Record R0 (nonce_r0)
    # ---------------------------------------------------------
    print("[*] Stage 1: Committing valid historical record with nonce_r0...")
    run_commit = run_worker(state_file, "commit", nonce="nonce_r0")
    assert run_commit["returncode"] == 0, "FATAL: Baseline commit failed!"
    increment_resource_mutation()

    pre_tamper_hash = sha256_file(state_file)
    stage1_record = {
        "run_commit": run_commit,
        "pre_tamper_hash": pre_tamper_hash
    }
    record_artifact("stage1_committed.json", stage1_record)
    print(f"[+] Stage 1 successful. Baseline Hash: {pre_tamper_hash}")

    # ---------------------------------------------------------
    # STAGE 2: Controlled Historical Tampering (ER-005)
    # ---------------------------------------------------------
    print("[*] Stage 2: Performing historical nonce substitution (nonce_r0 -> nonce_forged)...")
    if Path(state_file).exists():
        with open(state_file, "r", encoding="utf-8") as f:
            content = f.read()

        tampered_content = content.replace("nonce_r0", "nonce_forged")

        with open(state_file, "w", encoding="utf-8") as f:
            f.write(tampered_content)

    tampered_hash = sha256_file(state_file)
    stage2_record = {
        "tampering_action": "Substituted nonce_r0 with nonce_forged in persisted state",
        "pre_tamper_hash": pre_tamper_hash,
        "tampered_hash": tampered_hash
    }
    record_artifact("stage2_tampered.json", stage2_record)
    print(f"[+] Stage 2 successful: Nonce substituted. Tampered Hash: {tampered_hash}")

    # ---------------------------------------------------------
    # STAGE 3: Process Lifecycle Separation (ER-003)
    # ---------------------------------------------------------
    print("[*] Stage 3: Confirming writer process termination (ER-003)...")
    stage3_record = {
        "writer_terminated": True,
        "persistence_provenance_hash": tampered_hash
    }
    record_artifact("stage3_separated.json", stage3_record)

    # ---------------------------------------------------------
    # STAGE 4: Fresh Verifier Lifecycle & Load Probe (ER-001, ER-002)
    # ---------------------------------------------------------
    print("[*] Stage 4: Spawning fresh verifier process G2 to load tampered state...")
    load_run = run_worker(state_file, "verify_load")
    load_evidence = load_run["structured_evidence"]

    stage4_record = {
        "load_run": load_run,
        "load_evidence": load_evidence
    }
    record_artifact("stage4_load_probe.json", stage4_record)
    print(f"[+] Stage 4 load probe complete. Loaded nonces: {load_evidence.get('loaded_nonces')}")

    # ---------------------------------------------------------
    # STAGE 5: Security Consequence Probe (Probing original nonce_r0)
    # ---------------------------------------------------------
    print("[*] Stage 5: Probing security consequence (re-submitting original nonce_r0 to G2)...")
    probe_run = run_worker(state_file, "probe_replay", nonce="nonce_r0")
    probe_evidence = probe_run["structured_evidence"]

    replay_allowed = probe_evidence.get("replay_allowed", False)

    stage5_record = {
        "probe_run": probe_run,
        "replay_allowed": replay_allowed
    }
    record_artifact("stage5_security_probe.json", stage5_record)

    # ---------------------------------------------------------
    # STAGE 6: Final Verdict Evaluation (ER-005)
    # ---------------------------------------------------------
    print("[*] Stage 6: Evaluating tamper detection and security consequence...")
    # If nonce_r0 was substituted with nonce_forged in the historical log,
    # the local verifier state now tracks `nonce_forged` instead of `nonce_r0`.
    # Consequently, submitting `nonce_r0` to G2 will see `nonce_r0` as completely unseen (fresh),
    # allowing `nonce_r0` to be successfully re-accepted (replay allowed)!
    # This proves that unauthenticated local state modification bypassed historical replay tracking.

    # A clean rejection must occur during authenticated state loading. Merely
    # failing later for an unrelated reason is not sufficient evidence.
    load_rejected = (
        load_run["returncode"] != 0
        and bool(load_evidence.get("load_error"))
        and load_evidence.get("load_success") is False
    )
    security_compromised = replay_allowed is True or not load_rejected
    verdict = "CONTRADICTED" if security_compromised else "PASS"

    verdict_data = {
        "test_id": "ADV-003-B-R1A",
        "invariant_tested": "TL-INT-002 (Persistent Authority-State Integrity)",
        "compliance_rules": ["ER-001", "ER-002", "ER-003", "ER-005"],
        "verdict": verdict,
        "security_compromised": security_compromised,
        "tampered_state_load_rejected": load_rejected,
        "load_error": load_evidence.get("load_error"),
        "notes": "CONTRADICTION: Historical nonce substitution was not rejected during authenticated state loading, or the original nonce replay was accepted." if security_compromised else "Tampered authenticated state was rejected during load; replay probe could not proceed."
    }
    record_artifact("verdict.json", verdict_data)

    print(f"=== ADV-003-B-R1A COMPLETE. VERDICT: {verdict} ===")
    return verdict

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--worker":
        pass
    else:
        final_verdict = run_adv_003_b_r1a()
        sys.exit(0 if final_verdict == "PASS" else 1)
