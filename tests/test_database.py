"""
tests/test_database.py - Unit Tests for SQLite Database Layer
Subject: Cryptography and Network Security
"""

import sqlite3
import pytest
from pathlib import Path
from database import Database


class TestDatabaseModule:

    @pytest.fixture
    def test_db(self, tmp_path: Path) -> Database:
        """Creates an isolated test database in a temporary directory."""
        db_file = tmp_path / "test_integrity.db"
        return Database(db_path=db_file)

    def test_database_initialization(self, test_db: Database):
        """Verifies tables and schema are created automatically."""
        stats = test_db.get_statistics()
        assert stats["total_registered"] == 0
        assert stats["total_verifications"] == 0

    def test_record_creation_and_retrieval(self, test_db: Database, tmp_path: Path):
        """10. Database record creation and retrieval."""
        sample_path = tmp_path / "sample.docx"
        sample_path.touch()
        sample_hash = "a" * 64

        file_id = test_db.register_file(sample_path, sample_hash, 1024)
        assert file_id > 0

        # Retrieve by path
        by_path = test_db.get_file_by_path(sample_path)
        assert by_path is not None
        assert by_path["id"] == file_id
        assert by_path["filename"] == "sample.docx"
        assert by_path["trusted_hash"] == sample_hash
        assert by_path["file_size"] == 1024

        # Retrieve by ID
        by_id = test_db.get_file_by_id(file_id)
        assert by_id == by_path

    def test_duplicate_registration_prevention(self, test_db: Database, tmp_path: Path):
        """Prevents duplicate baseline entries for the same absolute path."""
        p = tmp_path / "unique.txt"
        p.touch()

        test_db.register_file(p, "b" * 64, 500)
        with pytest.raises(sqlite3.IntegrityError):
            test_db.register_file(p, "c" * 64, 600)

    def test_update_baseline(self, test_db: Database, tmp_path: Path):
        """Allows updating baseline only through explicit update_baseline call."""
        p = tmp_path / "update_target.txt"
        p.touch()

        file_id = test_db.register_file(p, "1" * 64, 100)
        new_hash = "2" * 64

        success = test_db.update_baseline(file_id, new_hash, 250)
        assert success is True

        rec = test_db.get_file_by_id(file_id)
        assert rec["trusted_hash"] == new_hash
        assert rec["file_size"] == 250

    def test_verification_history_creation_and_filtering(self, test_db: Database, tmp_path: Path):
        """11. Verification history creation and retrieval with status filtering."""
        f1 = tmp_path / "file1.txt"
        f2 = tmp_path / "file2.txt"

        test_db.add_history_entry(
            file_path=f1,
            verification_result="INTEGRITY VERIFIED",
            expected_hash="h1",
            actual_hash="h1"
        )
        test_db.add_history_entry(
            file_path=f2,
            verification_result="FILE MODIFIED — HASH MISMATCH",
            expected_hash="h2",
            actual_hash="h3",
            error_details="Tampered"
        )

        all_hist = test_db.get_history()
        assert len(all_hist) == 2

        # Filter by status
        verified_only = test_db.get_history(status_filter="INTEGRITY VERIFIED")
        assert len(verified_only) == 1
        assert verified_only[0]["verification_result"] == "INTEGRITY VERIFIED"

        mismatches_only = test_db.get_history(status_filter="FILE MODIFIED — HASH MISMATCH")
        assert len(mismatches_only) == 1
        assert mismatches_only[0]["verification_result"] == "FILE MODIFIED — HASH MISMATCH"

    def test_delete_baseline(self, test_db: Database, tmp_path: Path):
        """Tests removing a baseline from the database."""
        p = tmp_path / "del.txt"
        p.touch()
        fid = test_db.register_file(p, "d" * 64, 50)
        assert test_db.delete_file(fid) is True
        assert test_db.get_file_by_id(fid) is None
