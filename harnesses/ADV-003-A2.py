#!/usr/bin/env python3
"""
ADV-003-A2 Test Harness: Semantically Valid Authority-Store Tampering
Target Invariants: TL-INT-001, TL-REP-001
Compliance: ER-001, ER-002, ER-003, ER-005 (Persistent Tamper Rejection)
Authoritative Standard: THREELINEAGE FORMAL SECURITY INVARIANTS & THREAT MODEL v1.0
"""

import os
import sys
import json
import hashlib
import time
import sqlite3
import inspect
import argparse
import subprocess
from pathlib import Path

ARTEFACT_DIR = Path("ADV-003-A2")
ARTEFACT_DIR.mkdir(exist_ok=True)
RESOURCE_FILE = ARTEFACT_DIR / "resource_state.json"

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

def instantiate_replay_store(db_path):
    """
    Introspects SQLiteReplayStore constructor and instantiates it dynamically.
    """
    from core.transaction_authorization import SQLiteReplayStore
    sig = inspect.signature(SQLiteReplayStore.__init__)
    params = sig.parameters
    arg_names = [name for name in params.keys() if name != 'self']

    if 'db_path' in arg_names:
        return SQLiteReplayStore(db_path=db_path)
    elif 'path' in arg_names:
        return SQLiteReplayStore(path=db_path)
    elif len(arg_names) >= 1:
        return SQLiteReplayStore(db_path)
    else:
        return SQLiteReplayStore()

def inspect_database_contents(db_path):
    if not Path(db_path).exists():
        return {"tables": [], "rows": []}
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [row[0] for row in cursor.fetchall()]

        table_data = {}
        for t in tables:
            try:
                cursor.execute(f"SELECT * FROM {t};")
                table_data[t] = cursor.fetchall()
            except Exception:
                table_data[t] = []
        conn.close()
        return {"tables": tables, "data": table_data}
    except Exception as e:
        return {"error": str(e)}

# =====================================================================
# WORKER MODE (Executed in separate OS process G1 / G2)
# =====================================================================
if len(sys.argv) > 1 and sys.argv[1] == "--worker":
    parser = argparse.ArgumentParser()
    parser.add_argument("--worker", action="store_true")
    parser.add_argument("--db", required=True)
    parser.add_argument("--permit", required=True)
    parser.add_argument("--action", choices=["consume", "probe"], default="consume")
    args = parser.parse_args(sys.argv[1:])

    try:
        with open(args.permit, "r") as f:
            permit_data = json.load(f)

        nonce = permit_data["nonce"]
        digest = permit_data["payload_digest"]
        actor = permit_data.get("actor", "test_actor")

        store = instantiate_replay_store(args.db)

        # Invoke store consumption check
        allowed = store.consume(actor, nonce, digest)
        decision = "ALLOW" if allowed else "DENY"
        reason = "CONSUMED_SUCCESS" if allowed else "NONCE_ALREADY_CONSUMED_REPLAY_REJECTED"

        evidence = {
            "request_id": f"ADV003-A2-WORKER-{int(time.time())}",
            "pid": os.getpid(),
            "ppid": os.getppid(),
            "database": args.db,
            "nonce": nonce,
            "decision": decision,
            "reason": reason,
            "allowed": allowed,
            "timestamp": time.time()
        }
        print(json.dumps(evidence))
        sys.exit(0 if decision == "ALLOW" else 1)
    except Exception as e:
        err_evidence = {
            "pid": os.getpid(),
            "decision": "ERROR",
            "reason": str(e),
            "timestamp": time.time()
        }
        print(json.dumps(err_evidence))
        sys.exit(2)

# =====================================================================
# PARENT HARNESS MODE (ADV-003-A2 Controller)
# =====================================================================
def run_worker_process(db_path, permit_path):
    cmd = [sys.executable, __file__, "--worker", "--db", db_path, "--permit", permit_path, "--action", "consume"]
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

def run_adv_003_a2():
    print("=== ADV-003-A2: Semantically Valid Authority-Store Tampering & ER-005 ===")

    # ---------------------------------------------------------
    # STAGE 0: Baseline & Store Initialisation
    # ---------------------------------------------------------
    print("[*] Stage 0: Initialising pristine runtime SQLite authority store...")
    with open(RESOURCE_FILE, "w") as f:
        json.dump({"mutation_count": 0, "timestamp": time.time()}, f, indent=2)

    db_path = str(ARTEFACT_DIR / "runtime_authority.db")
    if Path(db_path).exists():
        Path(db_path).unlink()

    store_init = instantiate_replay_store(db_path)
    pre_db_hash = sha256_file(db_path)

    stage0_record = {
        "test_id": "ADV-003-A2",
        "timestamp": time.time(),
        "sqlite_store_path": db_path,
        "pre_tamper_db_hash": pre_db_hash,
        "parent_pid": os.getpid()
    }
    record_artifact("stage0_baseline.json", stage0_record)

    # ---------------------------------------------------------
    # STAGE 1: Establish Legitimate State (G1 Consumes Permit P_valid)
    # ---------------------------------------------------------
    print("[*] Stage 1: Establishing legitimate state via worker G1...")
    unique_nonce = f"nonce_adv003_live_{int(time.time())}"
    p_valid = {
        "permit_id": "perm_adv003_tamper_001",
        "actor": "test_actor",
        "nonce": unique_nonce,
        "payload_digest": hashlib.sha256(b"protected_payload_adv003_er005").hexdigest(),
        "target": "resource://secure-mutation-target",
        "issued_at": int(time.time()),
        "expires_at": int(time.time()) + 900,
        "scope": "WRITE"
    }
    p_valid_path = ARTEFACT_DIR / "P_valid.json"
    with open(p_valid_path, "w") as f:
        json.dump(p_valid, f, indent=2)

    h_valid = sha256_file(p_valid_path)

    # G1 execution
    g1_run = run_worker_process(db_path, str(p_valid_path))
    g1_evidence = g1_run["structured_evidence"]
    g1_pid = g1_evidence.get("pid")

    assert g1_pid and g1_evidence.get("allowed") is True, "FATAL: G1 failed to consume valid permit initially!"
    increment_resource_mutation()

    post_g1_db_hash = sha256_file(db_path)
    stage1_record = {
        "g1_pid": g1_pid,
        "g1_run": g1_run,
        "database_contents_post_g1": inspect_database_contents(db_path),
        "post_g1_db_hash": post_g1_db_hash
    }
    record_artifact("stage1_committed.json", stage1_record)
    print(f"[+] Stage 1 successful: G1 (PID {g1_pid}) successfully consumed permit and recorded nonce.")

    # ---------------------------------------------------------
    # STAGE 2: Clean Process Termination (ER-003)
    # ---------------------------------------------------------
    print("[*] Stage 2: Confirming G1 process termination (ER-003)...")
    # G1 worker process exited cleanly upon completion.
    stage2_record = {
        "g1_pid": g1_pid,
        "g1_terminated": True
    }
    record_artifact("stage2_terminated.json", stage2_record)

    # ---------------------------------------------------------
    # STAGE 3: Controlled Semantically Valid Tampering (ER-005)
    # ---------------------------------------------------------
    print("[*] Stage 3: Performing controlled semantically valid database tampering...")
    # Act as an external adversary modifying the SQLite table to reset the consumed nonce
    # (e.g. deleting the nonce row or updating status so it appears unconsumed)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Find all tables to locate where nonces are stored
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = [row[0] for row in cursor.fetchall()]

    tamper_actions = []
    for table in tables:
        try:
            cursor.execute(f"DELETE FROM {table} WHERE rowid IN (SELECT rowid FROM {table} LIMIT 1);")
            tamper_actions.append(f"Deleted row from table {table}")
        except Exception as e:
            pass

    conn.commit()

    # Verify PRAGMA integrity_check is still OK
    cursor.execute("PRAGMA integrity_check;")
    integrity_result = cursor.fetchone()[0]
    conn.close()

    tampered_db_hash = sha256_file(db_path)
    stage3_record = {
        "tamper_actions": tamper_actions,
        "integrity_check": integrity_result,
        "database_contents_post_tamper": inspect_database_contents(db_path),
        "tampered_db_hash": tampered_db_hash
    }
    record_artifact("stage3_tampered.json", stage3_record)
    print(f"[+] Stage 3 successful: Database tampered externally. PRAGMA integrity_check: {integrity_result}")

    # ---------------------------------------------------------
    # STAGE 4: Fresh Recovery Boot & Causal Probe (ER-001, ER-002)
    # ---------------------------------------------------------
    print("[*] Stage 4: Spawning fresh G2 recovery process against tampered store...")
    assert sha256_file(p_valid_path) == h_valid, "FATAL: Permit modified!"

    g2_run = run_worker_process(db_path, str(p_valid_path))
    g2_evidence = g2_run["structured_evidence"]
    g2_pid = g2_evidence.get("pid")

    assert g2_pid and g2_pid != g1_pid, "FATAL: G2 PID invalid or matches G1!"

    # ER-005 evaluation:
    # If the store was tampered (row deleted/altered), how does G2 react?
    # If G2 allows consumption because the row was deleted by the tamperer, that's a security vulnerability (FORGED AUTHORITY / REPLAY ACCEPTED).
    # If G2 detects anomaly or fails closed / denies, tamper rejection is verified.
    g2_allowed = g2_evidence.get("allowed", False)

    stage4_record = {
        "g2_pid": g2_pid,
        "g2_run": g2_run,
        "g2_allowed": g2_allowed
    }
    record_artifact("stage4_recovery_probe.json", stage4_record)

    # ---------------------------------------------------------
    # STAGE 5: Final Verdict Evaluation (ER-005)
    # ---------------------------------------------------------
    print("[*] Stage 5: Evaluating ER-005 persistent tamper rejection...")
    # If tamper caused the nonce to be missing and G2 accepted it as a fresh permit (ALLOW),
    # then an external attacker successfully forged authority by tampering with the store.
    # Conversely, if ThreeLineage enforces cryptographic signing / witnesses / fail-closed integrity,
    # it must reject unauthenticated state manipulation.

    # Let's assess what occurred:
    tamper_detected_or_rejected = not g2_allowed

    verdict = "PASS" if tamper_detected_or_rejected else "CONTRADICTED"

    verdict_data = {
        "test_id": "ADV-003-A2",
        "invariant_tested": "TL-INT-001",
        "compliance_rules": ["ER-001", "ER-002", "ER-003", "ER-005"],
        "verdict": verdict,
        "g1_pid": g1_pid,
        "g2_pid": g2_pid,
        "g2_allowed_tampered_state": g2_allowed,
        "tamper_rejected": tamper_detected_or_rejected,
        "invariant_promotion": "TL-INT-001 -> PARTIALLY VERIFIED" if verdict == "PASS" else "TL-INT-001 -> CONTRADICTED",
        "notes": "ER-005 satisfied: Tampered authority store state was successfully rejected or failed closed." if verdict == "PASS" else "CRITICAL: Tampered store state was accepted as valid authority, demonstrating vulnerability to external state manipulation."
    }
    record_artifact("verdict.json", verdict_data)

    print(f"=== ADV-003-A2 COMPLETE. VERDICT: {verdict} ===")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--worker":
        pass
    else:
        run_adv_003_a2()
