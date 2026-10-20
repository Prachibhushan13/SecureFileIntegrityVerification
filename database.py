"""
database.py - SQLite3 Database Management Module
Part of 'Secure File Integrity Verification Using SHA-256'
Subject: Cryptography and Network Security

Manages trusted baseline records and verification history using SQLite3.
All queries use parameterized statements to prevent SQL injection vulnerabilities.
Database tables are created automatically on application startup.
"""

import sqlite3
import logging
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

DEFAULT_DB_FILE = Path(__file__).resolve().parent / "file_integrity.db"


class Database:
    """Encapsulates SQLite connection management and CRUD operations."""

    def __init__(self, db_path: Optional[str | Path] = None):
        self.db_path = Path(db_path) if db_path else DEFAULT_DB_FILE
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        """Creates a SQLite connection with row factory enabled."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn

    def _init_db(self) -> None:
        """Initializes tables and indexes if they do not exist."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Files table: stores trusted baselines
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    filename TEXT NOT NULL,
                    absolute_path TEXT UNIQUE NOT NULL,
                    trusted_hash TEXT NOT NULL,
                    file_size INTEGER NOT NULL,
                    registration_timestamp TEXT NOT NULL,
                    last_verification_timestamp TEXT,
                    last_verification_status TEXT
                );
            """)

            # Verification history table: stores audit logs of all checks
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS verification_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_id INTEGER,
                    file_path TEXT NOT NULL,
                    expected_hash TEXT,
                    actual_hash TEXT,
                    verification_result TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    error_details TEXT,
                    FOREIGN KEY(file_id) REFERENCES files(id) ON DELETE SET NULL
                );
            """)

            # Useful indexes for fast lookups
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_files_path
                ON files (absolute_path);
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_history_timestamp
                ON verification_history (timestamp DESC);
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_history_result
                ON verification_history (verification_result);
            """)

            conn.commit()
            logger.info(f"Database initialized at {self.db_path}")

    # =========================================================================
    # Files Table Operations (Baselines)
    # =========================================================================

    def register_file(
        self,
        file_path: str | Path,
        trusted_hash: str,
        file_size: int
    ) -> int:
        """
        Registers a new file baseline in the database.

        Raises:
            sqlite3.IntegrityError: If file path already exists.
        """
        path_obj = Path(file_path).resolve()
        now = datetime.now().isoformat(timespec="seconds")

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO files (
                    filename, absolute_path, trusted_hash, file_size,
                    registration_timestamp, last_verification_timestamp, last_verification_status
                ) VALUES (?, ?, ?, ?, ?, NULL, 'PENDING')
            """, (path_obj.name, str(path_obj), trusted_hash.lower(), file_size, now))
            conn.commit()
            return cursor.lastrowid

    def update_baseline(
        self,
        file_id: int,
        new_trusted_hash: str,
        new_file_size: int
    ) -> bool:
        """
        Updates an existing file baseline after explicit user confirmation.
        """
        now = datetime.now().isoformat(timespec="seconds")
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE files
                SET trusted_hash = ?,
                    file_size = ?,
                    registration_timestamp = ?,
                    last_verification_status = 'UPDATED BASELINE'
                WHERE id = ?
            """, (new_trusted_hash.lower(), new_file_size, now, file_id))
            conn.commit()
            return cursor.rowcount > 0

    def get_file_by_path(self, file_path: str | Path) -> Optional[Dict[str, Any]]:
        """Retrieves a baseline record by its normalized absolute path."""
        path_str = str(Path(file_path).resolve())
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM files WHERE absolute_path = ?", (path_str,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_file_by_id(self, file_id: int) -> Optional[Dict[str, Any]]:
        """Retrieves a baseline record by primary key."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM files WHERE id = ?", (file_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_all_files(self) -> List[Dict[str, Any]]:
        """Returns all registered baselines ordered by filename."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM files ORDER BY id DESC")
            return [dict(row) for row in cursor.fetchall()]

    def update_file_status(
        self,
        file_id: int,
        status: str,
        timestamp: Optional[str] = None
    ) -> None:
        """Updates the last verification result and timestamp for a file."""
        ts = timestamp or datetime.now().isoformat(timespec="seconds")
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE files
                SET last_verification_status = ?,
                    last_verification_timestamp = ?
                WHERE id = ?
            """, (status, ts, file_id))
            conn.commit()

    def delete_file(self, file_id: int) -> bool:
        """Deletes a registered file baseline."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM files WHERE id = ?", (file_id,))
            conn.commit()
            return cursor.rowcount > 0

    # =========================================================================
    # Verification History Operations
    # =========================================================================

    def add_history_entry(
        self,
        file_path: str | Path,
        verification_result: str,
        expected_hash: Optional[str] = None,
        actual_hash: Optional[str] = None,
        file_id: Optional[int] = None,
        error_details: Optional[str] = None,
        timestamp: Optional[str] = None
    ) -> int:
        """Logs a verification attempt in the verification_history table."""
        ts = timestamp or datetime.now().isoformat(timespec="seconds")
        path_str = str(Path(file_path).resolve())

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO verification_history (
                    file_id, file_path, expected_hash, actual_hash,
                    verification_result, timestamp, error_details
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                file_id,
                path_str,
                expected_hash.lower() if expected_hash else None,
                actual_hash.lower() if actual_hash else None,
                verification_result,
                ts,
                error_details
            ))
            conn.commit()
            return cursor.lastrowid

    def get_history(
        self,
        status_filter: Optional[str] = None,
        search_term: Optional[str] = None,
        limit: int = 200
    ) -> List[Dict[str, Any]]:
        """
        Retrieves verification history with optional filtering and search.
        """
        query = "SELECT * FROM verification_history WHERE 1=1"
        params: List[Any] = []

        if status_filter and status_filter.upper() != "ALL":
            query += " AND verification_result = ?"
            params.append(status_filter)

        if search_term and search_term.strip():
            query += " AND (file_path LIKE ? OR expected_hash LIKE ? OR actual_hash LIKE ?)"
            wildcard = f"%{search_term.strip()}%"
            params.extend([wildcard, wildcard, wildcard])

        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, tuple(params))
            return [dict(row) for row in cursor.fetchall()]

    def clear_history(self) -> int:
        """Clears all verification history records."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM verification_history")
            conn.commit()
            return cursor.rowcount

    # =========================================================================
    # Aggregations & Dashboard Statistics
    # =========================================================================

    def get_statistics(self) -> Dict[str, int]:
        """Calculates summary statistics for the dashboard cards."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Registered files count
            cursor.execute("SELECT COUNT(*) FROM files")
            total_registered = cursor.fetchone()[0]

            # Total verification attempts
            cursor.execute("SELECT COUNT(*) FROM verification_history")
            total_verifications = cursor.fetchone()[0]

            # Verified clean count
            cursor.execute("""
                SELECT COUNT(*) FROM verification_history
                WHERE verification_result = 'INTEGRITY VERIFIED'
            """)
            verified_success = cursor.fetchone()[0]

            # Tampering/Mismatch count
            cursor.execute("""
                SELECT COUNT(*) FROM verification_history
                WHERE verification_result = 'FILE MODIFIED — HASH MISMATCH'
            """)
            tampering_detected = cursor.fetchone()[0]

            # Errors / Not Found count
            cursor.execute("""
                SELECT COUNT(*) FROM verification_history
                WHERE verification_result NOT IN ('INTEGRITY VERIFIED', 'FILE MODIFIED — HASH MISMATCH')
            """)
            other_issues = cursor.fetchone()[0]

            return {
                "total_registered": total_registered,
                "total_verifications": total_verifications,
                "verified_success": verified_success,
                "tampering_detected": tampering_detected,
                "other_issues": other_issues
            }
