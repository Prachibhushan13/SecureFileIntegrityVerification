"""
main.py - Entry Point for Secure File Integrity Verification Using SHA-256
Subject: Cryptography and Network Security

Usage:
    python3 main.py                 # Launches the Desktop Tkinter GUI
    python3 main.py --demo          # Runs automated demonstration scenario
    python3 main.py --register <f>  # Registers a file baseline from terminal
    python3 main.py --verify <f>    # Verifies file integrity from terminal
    python3 main.py --verify-all    # Verifies all registered baselines
    python3 main.py --list          # Lists all registered baselines
    python3 main.py --history       # Displays verification audit history
"""

import sys
import argparse
import logging
from pathlib import Path

from database import Database
from integrity_service import (
    IntegrityService, STATUS_VERIFIED, STATUS_MODIFIED,
    STATUS_NOT_REGISTERED, STATUS_NOT_FOUND, STATUS_ERROR
)
from report_generator import generate_text_report, export_history_to_csv

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("main")


def run_gui() -> None:
    """Launches the Tkinter Desktop Application."""
    try:
        import tkinter as tk
        from gui.dashboard import DashboardApp
        app = DashboardApp()
        app.mainloop()
    except Exception as e:
        logger.error(f"Failed to launch GUI: {e}")
        print(f"\n[ERROR] Could not initialize graphical user interface: {e}")
        print("Tip: If running in a headless environment without an X server / display,")
        print("use command line arguments (e.g. `python3 main.py --demo` or `python3 main.py --verify <file>`).")
        sys.exit(1)


def run_cli_register(service: IntegrityService, file_path: str, overwrite: bool = False) -> None:
    """Registers a file baseline from the command line."""
    p = Path(file_path).resolve()
    success, msg, rec = service.register_file(p, allow_overwrite=overwrite)
    if success:
        print(f"[SUCCESS] {msg}")
        print(f"  File     : {rec['filename']}")
        print(f"  Path     : {rec['absolute_path']}")
        print(f"  SHA-256  : {rec['trusted_hash']}")
        print(f"  Size     : {rec['file_size']:,} bytes")
    else:
        print(f"[FAILED] {msg}")
        sys.exit(1)


def run_cli_verify(service: IntegrityService, file_path: str, save_report: bool = True) -> None:
    """Verifies a file integrity from the command line."""
    p = Path(file_path).resolve()
    res = service.verify_file(p)

    status_icon = "✓" if res.status == STATUS_VERIFIED else "✕"
    print("\n" + "=" * 70)
    print(f"INTEGRITY VERIFICATION RESULT: [{status_icon} {res.status}]")
    print("=" * 70)
    print(f"File Path    : {res.file_path}")
    print(f"Expected Hash: {res.expected_hash or 'None'}")
    print(f"Actual Hash  : {res.actual_hash or 'None'}")
    print(f"Hash Match   : {'YES (Bit-for-bit identical)' if res.hash_match else 'NO'}")

    if res.differing_bits:
        pct = round((res.differing_bits / 256.0) * 100, 2)
        print(f"Avalanche    : {res.differing_bits}/256 bits changed ({pct}%)")

    if res.error_message:
        print(f"Details      : {res.error_message}")
    print("=" * 70)

    if save_report:
        report_txt = generate_text_report(res)
        print("A verification report has been automatically generated in the reports/ directory.")

    if res.status != STATUS_VERIFIED:
        sys.exit(2)


def run_cli_verify_all(service: IntegrityService) -> None:
    """Performs batch integrity verification for all registered files."""
    results = service.verify_all_registered()
    if not results:
        print("No baseline files are currently registered in the database.")
        return

    print("\n" + "=" * 75)
    print(f"{'Filename':<28} | {'Status':<32} | {'Match':<6}")
    print("-" * 75)
    for r in results:
        m = "YES" if r.hash_match else "NO"
        print(f"{r.filename[:26]:<28} | {r.status[:30]:<32} | {m:<6}")
    print("=" * 75)


def run_cli_list(db: Database) -> None:
    """Lists all registered baseline files."""
    files = db.get_all_files()
    if not files:
        print("No files registered yet.")
        return

    print(f"\nRegistered Baselines ({len(files)} total):")
    print("-" * 85)
    print(f"{'ID':<4} | {'Filename':<24} | {'SHA-256 Digest':<34} | {'Last Status'}")
    print("-" * 85)
    for f in files:
        h = f["trusted_hash"][:30] + "..."
        st = f.get("last_verification_status") or "PENDING"
        print(f"{f['id']:<4} | {f['filename'][:22]:<24} | {h:<34} | {st}")
    print("-" * 85)


def run_cli_history(db: Database) -> None:
    """Displays verification audit history."""
    records = db.get_history(limit=50)
    if not records:
        print("No verification history recorded yet.")
        return

    print(f"\nVerification History (Last {len(records)} entries):")
    print("-" * 85)
    print(f"{'ID':<4} | {'Timestamp':<19} | {'Result':<30} | {'File Path'}")
    print("-" * 85)
    for r in records:
        fname = Path(r["file_path"]).name
        print(f"{r['id']:<4} | {r['timestamp']:<19} | {r['verification_result'][:28]:<30} | {fname}")
    print("-" * 85)


def main():
    parser = argparse.ArgumentParser(
        description="Secure File Integrity Verification Using SHA-256 (Cryptography and Network Security)"
    )
    parser.add_argument("--register", metavar="FILE", help="Register a file's SHA-256 trusted baseline")
    parser.add_argument("--overwrite", action="store_true", help="Force overwrite of an existing baseline")
    parser.add_argument("--verify", metavar="FILE", help="Verify integrity of a file against registered baseline")
    parser.add_argument("--verify-all", action="store_true", help="Verify all registered baseline files")
    parser.add_argument("--list", action="store_true", help="List all registered baseline files")
    parser.add_argument("--history", action="store_true", help="Display verification history logs")
    parser.add_argument("--demo", action="store_true", help="Run the automated college demonstration scenario")

    args = parser.parse_args()

    # If no flags provided, launch the GUI
    if len(sys.argv) == 1:
        run_gui()
        return

    db = Database()
    service = IntegrityService(db)

    if args.demo:
        from demo_walkthrough import run_full_demonstration
        run_full_demonstration()
    elif args.register:
        run_cli_register(service, args.register, overwrite=args.overwrite)
    elif args.verify:
        run_cli_verify(service, args.verify)
    elif args.verify_all:
        run_cli_verify_all(service)
    elif args.list:
        run_cli_list(db)
    elif args.history:
        run_cli_history(db)


if __name__ == "__main__":
    main()
