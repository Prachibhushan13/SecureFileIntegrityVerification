"""
tests/test_integrity.py - Unit Tests for Integrity Verification Service
Subject: Cryptography and Network Security
"""

import pytest
from pathlib import Path
from database import Database
from integrity_service import (
    IntegrityService, STATUS_VERIFIED, STATUS_MODIFIED,
    STATUS_NOT_REGISTERED, STATUS_NOT_FOUND, STATUS_ERROR
)


class TestIntegrityService:

    @pytest.fixture
    def service(self, tmp_path: Path) -> IntegrityService:
        db = Database(db_path=tmp_path / "test_service.db")
        return IntegrityService(db=db)

    def test_successful_registration_and_verification(self, service: IntegrityService, tmp_path: Path):
        """8. Successful registration and verification of an intact file."""
        test_file = tmp_path / "report.pdf"
        test_file.write_text("Confidential Department Project Report 2026", encoding="utf-8")

        # Register
        ok, msg, rec = service.register_file(test_file)
        assert ok is True
        assert rec is not None
        assert rec["filename"] == "report.pdf"

        # Verify
        result = service.verify_file(test_file)
        assert result.status == STATUS_VERIFIED
        assert result.hash_match is True
        assert result.expected_hash == result.actual_hash
        assert result.expected_hash == rec["trusted_hash"]

    def test_mismatched_hash_detection(self, service: IntegrityService, tmp_path: Path):
        """9. Detection of mismatched hashes after tampering."""
        test_file = tmp_path / "code.py"
        test_file.write_text("ALLOW_ACCESS = False", encoding="utf-8")

        # Register
        service.register_file(test_file)

        # Tamper with file
        test_file.write_text("ALLOW_ACCESS = True", encoding="utf-8")

        # Verify
        result = service.verify_file(test_file)
        assert result.status == STATUS_MODIFIED
        assert result.hash_match is False
        assert result.expected_hash != result.actual_hash
        assert result.differing_bits is not None
        assert result.differing_bits > 0

    def test_unregistered_file_verification(self, service: IntegrityService, tmp_path: Path):
        """7. Handling of unregistered files."""
        unregistered = tmp_path / "stranger.txt"
        unregistered.write_text("I am not registered", encoding="utf-8")

        result = service.verify_file(unregistered)
        assert result.status == STATUS_NOT_REGISTERED
        assert result.expected_hash is None
        assert result.actual_hash is not None  # Still computes current hash for inspection

    def test_missing_registered_file_handling(self, service: IntegrityService, tmp_path: Path):
        """Handling of registered file that is deleted or missing from disk."""
        transient_file = tmp_path / "temporary.txt"
        transient_file.write_text("Data to be deleted", encoding="utf-8")

        service.register_file(transient_file)

        # Delete file from disk
        transient_file.unlink()

        result = service.verify_file(transient_file)
        assert result.status == STATUS_NOT_FOUND
        assert result.actual_hash is None
        assert result.expected_hash is not None

    def test_prevention_of_accidental_baseline_replacement(self, service: IntegrityService, tmp_path: Path):
        """12. Prevention of accidental baseline replacement (never silently overwrite)."""
        target = tmp_path / "contract.txt"
        target.write_text("Version 1.0 Original Agreement", encoding="utf-8")

        ok1, _, rec1 = service.register_file(target, allow_overwrite=False)
        assert ok1 is True
        original_hash = rec1["trusted_hash"]

        # Modify file
        target.write_text("Version 2.0 Altered Agreement", encoding="utf-8")

        # Attempt to register again without allow_overwrite
        ok2, err_msg, _ = service.register_file(target, allow_overwrite=False)
        assert ok2 is False
        assert "Explicit confirmation is required" in err_msg

        # Verify that stored baseline is still Version 1.0 hash
        db_rec = service.db.get_file_by_path(target)
        assert db_rec["trusted_hash"] == original_hash

        # Now test with explicit overwrite allowed
        ok3, success_msg, rec3 = service.register_file(target, allow_overwrite=True)
        assert ok3 is True
        assert rec3["trusted_hash"] != original_hash

    def test_chunked_reading_large_file(self, service: IntegrityService, tmp_path: Path):
        """Verifies chunked hashing for files larger than default chunk size (64KB)."""
        large_file = tmp_path / "large_payload.bin"
        # 250 KB file (exceeds standard 64 KB chunk)
        chunk_data = b"X" * 65536 + b"Y" * 65536 + b"Z" * 65536 + b"W" * 50000
        large_file.write_bytes(chunk_data)

        ok, _, rec = service.register_file(large_file)
        assert ok is True

        res = service.verify_file(large_file)
        assert res.status == STATUS_VERIFIED
        assert res.file_size == len(chunk_data)

    def test_batch_verification(self, service: IntegrityService, tmp_path: Path):
        """Tests verifying multiple registered files in a single batch."""
        f1 = tmp_path / "f1.txt"
        f2 = tmp_path / "f2.txt"
        f1.write_text("file 1 content", encoding="utf-8")
        f2.write_text("file 2 content", encoding="utf-8")

        service.register_file(f1)
        service.register_file(f2)

        # Alter f2
        f2.write_text("file 2 tampered!", encoding="utf-8")

        results = service.verify_all_registered()
        assert len(results) == 2

        f1_res = next(r for r in results if r.filename == "f1.txt")
        f2_res = next(r for r in results if r.filename == "f2.txt")

        assert f1_res.status == STATUS_VERIFIED
        assert f2_res.status == STATUS_MODIFIED
