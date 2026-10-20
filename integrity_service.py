"""
integrity_service.py - Core File Integrity Verification Service
Part of 'Secure File Integrity Verification Using SHA-256'
Subject: Cryptography and Network Security

This service implements the business logic for file baseline registration,
SHA-256 hash comparison, tampering detection, and audit logging.
Baseline registrations and verifications are strictly decoupled to prevent
accidental or automatic baseline updates upon tampering detection.
"""

import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Tuple, Optional, List
from dataclasses import dataclass, asdict

from hashing import calculate_file_sha256, HashingError
from database import Database

logger = logging.getLogger(__name__)

# Standard Verification Status Strings as required
STATUS_VERIFIED = "INTEGRITY VERIFIED"
STATUS_MODIFIED = "FILE MODIFIED — HASH MISMATCH"
STATUS_NOT_REGISTERED = "FILE NOT REGISTERED"
STATUS_NOT_FOUND = "FILE NOT FOUND"
STATUS_ERROR = "VERIFICATION ERROR"


@dataclass
class VerificationResult:
    """Encapsulates the complete result of a file integrity verification."""
    status: str
    file_path: str
    filename: str
    expected_hash: Optional[str] = None
    actual_hash: Optional[str] = None
    hash_match: bool = False
    file_size: Optional[int] = None
    registered_timestamp: Optional[str] = None
    verification_timestamp: str = ""
    error_message: Optional[str] = None
    differing_bits: Optional[int] = None
    history_id: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class IntegrityService:
    """Coordinates hashing and database operations for file integrity checks."""

    def __init__(self, db: Optional[Database] = None):
        self.db = db or Database()

    # =========================================================================
    # File Registration
    # =========================================================================

    def register_file(
        self,
        file_path: str | Path,
        allow_overwrite: bool = False
    ) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """
        Calculates SHA-256 baseline and registers file in the database.

        Args:
            file_path: Target file path.
            allow_overwrite: If True, explicitly allows updating an existing baseline.

        Returns:
            Tuple of (success_bool, message_str, file_record_dict_or_none)
        """
        path = Path(file_path).resolve()

        if not path.exists():
            return False, f"Cannot register: File does not exist ({path})", None

        if path.is_dir():
            return False, f"Cannot register: Path is a directory, not a regular file ({path})", None

        try:
            current_hash = calculate_file_sha256(path)
            file_size = path.stat().st_size
        except (PermissionError, HashingError, OSError) as e:
            return False, f"Failed to compute SHA-256 hash: {e}", None

        existing_record = self.db.get_file_by_path(path)

        if existing_record:
            if not allow_overwrite:
                return (
                    False,
                    f"File is already registered with trusted hash:\n{existing_record['trusted_hash']}\n\n"
                    "Explicit confirmation is required to update an existing baseline.",
                    existing_record
                )
            else:
                # Update existing baseline
                self.db.update_baseline(existing_record["id"], current_hash, file_size)
                updated_record = self.db.get_file_by_id(existing_record["id"])
                logger.info(f"Updated baseline for file {path.name}")
                return True, f"Successfully updated trusted baseline for '{path.name}'", updated_record
        else:
            # Insert new record
            file_id = self.db.register_file(path, current_hash, file_size)
            new_record = self.db.get_file_by_id(file_id)
            logger.info(f"Registered new baseline for file {path.name} (ID: {file_id})")
            return True, f"Successfully registered trusted baseline for '{path.name}'", new_record

    # =========================================================================
    # File Integrity Verification
    # =========================================================================

    def verify_file(self, file_path: str | Path) -> VerificationResult:
        """
        Verifies the integrity of a file against its registered baseline.
        Does NOT alter the baseline under any circumstances.
        """
        path = Path(file_path).resolve()
        now = datetime.now().isoformat(timespec="seconds")
        existing_record = self.db.get_file_by_path(path)

        # 1. Check if file is registered in the database
        if not existing_record:
            # File is not registered. Compute current hash if readable for display.
            actual_hash = None
            if path.exists() and path.is_file():
                try:
                    actual_hash = calculate_file_sha256(path)
                except Exception:
                    pass

            hist_id = self.db.add_history_entry(
                file_path=path,
                verification_result=STATUS_NOT_REGISTERED,
                expected_hash=None,
                actual_hash=actual_hash,
                file_id=None,
                error_details="No baseline record found in database for this file path.",
                timestamp=now
            )
            return VerificationResult(
                status=STATUS_NOT_REGISTERED,
                file_path=str(path),
                filename=path.name,
                expected_hash=None,
                actual_hash=actual_hash,
                hash_match=False,
                verification_timestamp=now,
                error_message="File has not been registered in the trusted baseline database.",
                history_id=hist_id
            )

        file_id = existing_record["id"]
        expected_hash = existing_record["trusted_hash"]
        registered_ts = existing_record["registration_timestamp"]

        # 2. Check if file physically exists on disk
        if not path.exists():
            self.db.update_file_status(file_id, STATUS_NOT_FOUND, now)
            hist_id = self.db.add_history_entry(
                file_path=path,
                verification_result=STATUS_NOT_FOUND,
                expected_hash=expected_hash,
                actual_hash=None,
                file_id=file_id,
                error_details="Target file is missing or was deleted from the disk.",
                timestamp=now
            )
            return VerificationResult(
                status=STATUS_NOT_FOUND,
                file_path=str(path),
                filename=path.name,
                expected_hash=expected_hash,
                actual_hash=None,
                hash_match=False,
                registered_timestamp=registered_ts,
                verification_timestamp=now,
                error_message="The registered file could not be found at its recorded path.",
                history_id=hist_id
            )

        # 3. Calculate current SHA-256 hash
        try:
            actual_hash = calculate_file_sha256(path)
            file_size = path.stat().st_size
        except (PermissionError, HashingError, OSError) as e:
            error_msg = f"Read/Permission error: {e}"
            self.db.update_file_status(file_id, STATUS_ERROR, now)
            hist_id = self.db.add_history_entry(
                file_path=path,
                verification_result=STATUS_ERROR,
                expected_hash=expected_hash,
                actual_hash=None,
                file_id=file_id,
                error_details=error_msg,
                timestamp=now
            )
            return VerificationResult(
                status=STATUS_ERROR,
                file_path=str(path),
                filename=path.name,
                expected_hash=expected_hash,
                actual_hash=None,
                hash_match=False,
                registered_timestamp=registered_ts,
                verification_timestamp=now,
                error_message=error_msg,
                history_id=hist_id
            )

        # 4. Compare expected vs actual SHA-256 hash
        is_match = (expected_hash.lower() == actual_hash.lower())

        if is_match:
            status = STATUS_VERIFIED
            differing_bits = 0
            err_details = None
        else:
            status = STATUS_MODIFIED
            # Calculate Hamming distance between expected and actual hashes
            bin1 = bin(int(expected_hash, 16))[2:].zfill(256)
            bin2 = bin(int(actual_hash, 16))[2:].zfill(256)
            differing_bits = sum(b1 != b2 for b1, b2 in zip(bin1, bin2))
            err_details = f"Hash mismatch detected! Differing bits: {differing_bits}/256"

        # Update file table status and log to history table
        self.db.update_file_status(file_id, status, now)
        hist_id = self.db.add_history_entry(
            file_path=path,
            verification_result=status,
            expected_hash=expected_hash,
            actual_hash=actual_hash,
            file_id=file_id,
            error_details=err_details,
            timestamp=now
        )

        return VerificationResult(
            status=status,
            file_path=str(path),
            filename=path.name,
            expected_hash=expected_hash,
            actual_hash=actual_hash,
            hash_match=is_match,
            file_size=file_size,
            registered_timestamp=registered_ts,
            verification_timestamp=now,
            error_message=err_details,
            differing_bits=differing_bits,
            history_id=hist_id
        )

    def verify_all_registered(self) -> List[VerificationResult]:
        """Performs batch integrity verification for all registered files."""
        all_files = self.db.get_all_files()
        results: List[VerificationResult] = []
        for file_rec in all_files:
            res = self.verify_file(file_rec["absolute_path"])
            results.append(res)
        return results

    def delete_baseline(self, file_id: int) -> bool:
        """Removes a baseline record from the database."""
        return self.db.delete_file(file_id)
