"""
report_generator.py - Integrity Verification Report Generator
Part of 'Secure File Integrity Verification Using SHA-256'
Subject: Cryptography and Network Security

Generates human-readable text reports and CSV export files for file integrity
verification results. In accordance with cybersecurity principles, all reports
include an explicit cryptographic disclaimer noting that a clean hash verification
confirms baseline integrity but does not prove a file is free from malware.
"""

import csv
import logging
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional
from integrity_service import VerificationResult, STATUS_VERIFIED

logger = logging.getLogger(__name__)

REPORTS_DIR = Path(__file__).resolve().parent / "reports"
REPORTS_DIR.mkdir(exist_ok=True)

SECURITY_DISCLAIMER = (
    "SECURITY NOTICE & CRYPTOGRAPHIC DISCLAIMER:\n"
    "1. Integrity verification using SHA-256 confirms that the target file is bit-for-bit\n"
    "   identical to its recorded baseline. It does NOT guarantee that the file is safe,\n"
    "   non-malicious, or malware-free (a malicious file with an unchanged hash remains malicious).\n"
    "2. Threat Model Limitation: If an adversary obtains administrative write access to both\n"
    "   the file storage and the local database, they can alter the file and recalculate the baseline.\n"
    "3. Best Practice Recommendation: For mission-critical environments, baseline databases\n"
    "   should be protected using Digital Signatures (PKI/RSA/ECDSA), HMACs with hardware-backed\n"
    "   keys (TPM/HSM), or stored on write-once, tamper-evident audit ledgers."
)


def generate_text_report(
    result: VerificationResult,
    output_path: Optional[str | Path] = None
) -> str:
    """
    Generates a structured, human-readable text verification report.

    Args:
        result: The VerificationResult dataclass.
        output_path: Optional file path to save the report. If None, saves to reports/ directory.

    Returns:
        The generated report text.
    """
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    timestamp_slug = datetime.now().strftime("%Y%m%d_%H%M%S")

    divider = "=" * 80
    subdivider = "-" * 80

    lines = [
        divider,
        "SECURE FILE INTEGRITY VERIFICATION REPORT",
        "Subject: Cryptography and Network Security (SHA-256)",
        divider,
        f"Generated At          : {now_str}",
        f"Verification Timestamp: {result.verification_timestamp}",
        f"Cryptographic Hash    : SHA-256 (256-bit Digest / FIPS PUB 180-4)",
        f"Target Filename       : {result.filename}",
        f"Target Absolute Path  : {result.file_path}",
        f"File Size on Disk     : {f'{result.file_size:,} bytes' if result.file_size is not None else 'N/A'}",
        f"Baseline Registered   : {result.registered_timestamp or 'Not registered'}",
        subdivider,
        "HASH COMPARISON RESULTS",
        subdivider,
        f"Trusted Baseline Hash : {result.expected_hash or 'None (File not registered)'}",
        f"Current Computed Hash : {result.actual_hash or 'None (File missing or unreadable)'}",
        f"Hash Match Status     : {'MATCH - No Bit Flips' if result.hash_match else 'MISMATCH or INCONCLUSIVE'}",
    ]

    if result.differing_bits is not None and result.differing_bits > 0:
        lines.append(f"Differing Digest Bits : {result.differing_bits} of 256 bits (Avalanche Effect observed)")

    lines.extend([
        subdivider,
        f"FINAL VERIFICATION STATUS: [{result.status}]",
        subdivider,
    ])

    if result.error_message:
        lines.extend([
            f"Diagnostics / Details : {result.error_message}",
            subdivider,
        ])

    lines.extend([
        "",
        SECURITY_DISCLAIMER,
        divider,
    ])

    report_content = "\n".join(lines) + "\n"

    # Save to file
    if output_path is None:
        safe_filename = "".join(c if c.isalnum() or c in "._-" else "_" for c in result.filename)
        out_file = REPORTS_DIR / f"report_{safe_filename}_{timestamp_slug}.txt"
    else:
        out_file = Path(output_path)

    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(report_content, encoding="utf-8")
    logger.info(f"Report written to {out_file}")

    return report_content


def export_history_to_csv(
    history_records: List[Dict[str, Any]],
    output_path: Optional[str | Path] = None
) -> Path:
    """
    Exports a list of verification history records to a CSV file.

    Args:
        history_records: List of dictionaries from the database history table.
        output_path: Optional destination CSV path.

    Returns:
        Path to the saved CSV file.
    """
    if output_path is None:
        timestamp_slug = datetime.now().strftime("%Y%m%d_%H%M%S")
        dest_path = REPORTS_DIR / f"verification_history_{timestamp_slug}.csv"
    else:
        dest_path = Path(output_path)

    dest_path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "id",
        "file_id",
        "file_path",
        "verification_result",
        "expected_hash",
        "actual_hash",
        "timestamp",
        "error_details"
    ]

    with open(dest_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in history_records:
            writer.writerow(row)

    logger.info(f"Exported {len(history_records)} history records to {dest_path}")
    return dest_path


def generate_batch_summary_report(
    results: List[VerificationResult],
    output_path: Optional[str | Path] = None
) -> str:
    """Generates a summary text report for a batch of verified files."""
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    timestamp_slug = datetime.now().strftime("%Y%m%d_%H%M%S")

    total = len(results)
    verified = sum(1 for r in results if r.status == STATUS_VERIFIED)
    modified = sum(1 for r in results if "MISMATCH" in r.status)
    other = total - verified - modified

    divider = "=" * 80
    lines = [
        divider,
        "BATCH FILE INTEGRITY VERIFICATION REPORT",
        "Subject: Cryptography and Network Security (SHA-256)",
        divider,
        f"Execution Time  : {now_str}",
        f"Files Inspected : {total}",
        f"Verified Clean  : {verified}",
        f"Tampered/Failed : {modified}",
        f"Other/Errors    : {other}",
        divider,
        f"{'Filename':<30} | {'Status':<32} | {'Match':<6}",
        "-" * 80,
    ]

    for r in results:
        match_str = "YES" if r.hash_match else "NO"
        lines.append(f"{r.filename[:28]:<30} | {r.status[:30]:<32} | {match_str:<6}")

    lines.extend([
        divider,
        "",
        SECURITY_DISCLAIMER,
        divider,
    ])

    content = "\n".join(lines) + "\n"
    if output_path is None:
        out_file = REPORTS_DIR / f"batch_report_{timestamp_slug}.txt"
    else:
        out_file = Path(output_path)

    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(content, encoding="utf-8")
    return content
