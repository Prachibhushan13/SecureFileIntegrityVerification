"""
demo_walkthrough.py - End-to-End Demonstration Scenario
Part of 'Secure File Integrity Verification Using SHA-256'
Subject: Cryptography and Network Security

Demonstrates the 9-step scenario:
1. Create a sample text file containing 'Original secure content'.
2. Register the file and save its trusted SHA-256 hash baseline in SQLite.
3. Verify the unchanged file and confirm 'INTEGRITY VERIFIED'.
4. Modify the file content to 'Modified secure content' (single word / single byte tamper).
5. Verify the file again and confirm 'FILE MODIFIED — HASH MISMATCH'.
6. Display expected vs actual hashes and compute differing bits (Avalanche effect).
7. Show the verification attempt logged in the history table.
8. Export the verification report to disk.
9. Confirm that the original baseline was NOT modified by the mismatch check.
"""

import os
import sys
import shutil
import tempfile
from pathlib import Path
from database import Database
from hashing import calculate_file_sha256, compute_avalanche_effect
from integrity_service import (
    IntegrityService, STATUS_VERIFIED, STATUS_MODIFIED
)
from report_generator import generate_text_report, export_history_to_csv


def print_step(step_num: int, title: str) -> None:
    print("\n" + "=" * 78)
    print(f"STEP {step_num}: {title.upper()}")
    print("=" * 78)


def run_full_demonstration() -> bool:
    print("\n" + "#" * 78)
    print("  COLLEGE MINI PROJECT DEMONSTRATION: FILE INTEGRITY VERIFICATION")
    print("  Subject: Cryptography and Network Security  |  Algorithm: SHA-256")
    print("#" * 78)

    # Use a dedicated demo directory
    demo_dir = Path(__file__).resolve().parent / "demo_data"
    demo_dir.mkdir(exist_ok=True)
    demo_file = demo_dir / "confidential_document.txt"
    demo_db_path = demo_dir / "demo_integrity.db"

    # Clean up any previous demo db
    if demo_db_path.exists():
        demo_db_path.unlink()

    db = Database(db_path=demo_db_path)
    service = IntegrityService(db=db)

    # -------------------------------------------------------------------------
    # STEP 1: Create sample text file
    # -------------------------------------------------------------------------
    print_step(1, "Create Sample Target File with Initial Content")
    original_content = "Original secure content"
    demo_file.write_text(original_content, encoding="utf-8")
    initial_hash = calculate_file_sha256(demo_file)
    print(f"Created file: {demo_file.name}")
    print(f"Location    : {demo_file.resolve()}")
    print(f"Content     : '{original_content}'")
    print(f"Initial Hash: {initial_hash}")

    # -------------------------------------------------------------------------
    # STEP 2: Register file and save trusted baseline in SQLite
    # -------------------------------------------------------------------------
    print_step(2, "Register File Baseline in SQLite Database")
    success, msg, record = service.register_file(demo_file, allow_overwrite=False)
    assert success, f"Failed to register baseline: {msg}"
    print(f"Registration Status: SUCCESS")
    print(f"Database Record ID : {record['id']}")
    print(f"Trusted Baseline   : {record['trusted_hash']}")
    print(f"Registered At      : {record['registration_timestamp']}")

    # -------------------------------------------------------------------------
    # STEP 3: Verify the unchanged file
    # -------------------------------------------------------------------------
    print_step(3, "Verify Unchanged File Integrity")
    res1 = service.verify_file(demo_file)
    print(f"Verification Result: [{res1.status}]")
    print(f"Expected Hash      : {res1.expected_hash}")
    print(f"Actual Hash        : {res1.actual_hash}")
    print(f"Hash Match Status  : {res1.hash_match}")
    assert res1.status == STATUS_VERIFIED, f"Expected {STATUS_VERIFIED}, got {res1.status}"
    assert res1.hash_match is True

    # -------------------------------------------------------------------------
    # STEP 4: Modify text to simulate tampering
    # -------------------------------------------------------------------------
    print_step(4, "Simulate Unauthorized Modification / Tampering")
    tampered_content = "Modified secure content"
    demo_file.write_text(tampered_content, encoding="utf-8")
    tampered_hash = calculate_file_sha256(demo_file)
    print(f"File altered to : '{tampered_content}'")
    print(f"New Hash on Disk: {tampered_hash}")

    # -------------------------------------------------------------------------
    # STEP 5: Verify the file again and detect mismatch
    # -------------------------------------------------------------------------
    print_step(5, "Verify File After Tampering - Detect Hash Mismatch")
    res2 = service.verify_file(demo_file)
    print(f"Verification Result: [{res2.status}]")
    print(f"Expected (Trusted) : {res2.expected_hash}")
    print(f"Actual (Tampered)  : {res2.actual_hash}")
    print(f"Hash Match Status  : {res2.hash_match}")
    assert res2.status == STATUS_MODIFIED, f"Expected {STATUS_MODIFIED}, got {res2.status}"
    assert res2.hash_match is False

    # -------------------------------------------------------------------------
    # STEP 6: Display Avalanche Effect analysis
    # -------------------------------------------------------------------------
    print_step(6, "Cryptographic Analysis: Avalanche Effect (Strict Avalanche Criterion)")
    avalanche = compute_avalanche_effect(original_content, tampered_content)
    print(f"Original String: '{original_content}'")
    print(f"Modified String: '{tampered_content}'")
    print(f"Differing Bits : {avalanche['differing_bits']} / 256 bits")
    print(f"Bit Flip Ratio : {avalanche['percentage_difference']}% (Target ~50%)")

    # -------------------------------------------------------------------------
    # STEP 7: Show verification attempt in history
    # -------------------------------------------------------------------------
    print_step(7, "Inspect Verification Audit History Log in SQLite")
    history = db.get_history()
    print(f"Total Audit Log Entries: {len(history)}")
    for entry in history:
        print(f"  Log #{entry['id']} [{entry['timestamp']}] - Result: {entry['verification_result']}")
        print(f"    Expected: {entry['expected_hash']}")
        print(f"    Actual  : {entry['actual_hash']}")
        if entry.get("error_details"):
            print(f"    Details : {entry['error_details']}")

    # -------------------------------------------------------------------------
    # STEP 8: Export verification report
    # -------------------------------------------------------------------------
    print_step(8, "Export Verification Reports (Text and CSV)")
    report_path = demo_dir / "demo_tampering_report.txt"
    report_text = generate_text_report(res2, output_path=report_path)
    csv_path = demo_dir / "demo_history_export.csv"
    export_history_to_csv(history, output_path=csv_path)

    print(f"Saved Text Report to: {report_path}")
    print(f"Saved CSV Log to    : {csv_path}")
    print("\n--- Snippet of Generated Report ---")
    print("\n".join(report_text.splitlines()[:20]))
    print("...")

    # -------------------------------------------------------------------------
    # STEP 9: Confirm baseline was NOT overwritten by the mismatch
    # -------------------------------------------------------------------------
    print_step(9, "Security Verification: Ensure Baseline Remained Untampered")
    current_baseline_rec = db.get_file_by_id(record["id"])
    print(f"Stored Trusted Baseline Hash : {current_baseline_rec['trusted_hash']}")
    print(f"Original Registered Hash     : {initial_hash}")
    assert current_baseline_rec["trusted_hash"] == initial_hash, "Security violation: Baseline was altered!"
    print("✓ CONFIRMED: Baseline remained intact! System refused automatic overwrite.")

    print("\n" + "#" * 78)
    print("  DEMONSTRATION SCENARIO COMPLETED WITH 100% SUCCESS!")
    print("#" * 78 + "\n")
    return True


if __name__ == "__main__":
    run_full_demonstration()
