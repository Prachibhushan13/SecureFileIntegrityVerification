"""
tests/test_hashing.py - Unit Tests for Cryptographic Hashing Module
Subject: Cryptography and Network Security
"""

import tempfile
import pytest
from pathlib import Path
from hashing import (
    calculate_file_sha256, calculate_string_sha256,
    calculate_bytes_sha256, compute_avalanche_effect,
    EMPTY_SHA256
)


class TestHashingModule:

    def test_nist_known_test_vectors(self):
        """1. SHA-256 calculation for known NIST test vector ('abc') and empty string."""
        # NIST standard test vector for 'abc'
        # ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        expected_abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        assert calculate_string_sha256("abc") == expected_abc

        # Empty string NIST vector
        assert calculate_string_sha256("") == EMPTY_SHA256

    def test_empty_file_hashing(self, tmp_path: Path):
        """5. Handling of an empty file (0 bytes)."""
        empty_file = tmp_path / "empty.dat"
        empty_file.write_bytes(b"")

        digest = calculate_file_sha256(empty_file)
        assert digest == EMPTY_SHA256

    def test_repeated_hashing_consistency(self, tmp_path: Path):
        """2. Repeated hashing of an unchanged file must produce identical digests."""
        test_file = tmp_path / "consistent.txt"
        test_file.write_text("Integrity Verification Consistency Check 2026", encoding="utf-8")

        digest1 = calculate_file_sha256(test_file)
        digest2 = calculate_file_sha256(test_file)
        digest3 = calculate_file_sha256(test_file)

        assert digest1 == digest2 == digest3
        assert len(digest1) == 64

    def test_one_byte_modification_detection(self, tmp_path: Path):
        """3. Detection of a one-byte modification in file contents."""
        orig_file = tmp_path / "target.bin"
        orig_data = b"Attack at dawn: 0600"
        orig_file.write_bytes(orig_data)
        hash_orig = calculate_file_sha256(orig_file)

        # Flip exactly 1 byte (from '0' to '1')
        tampered_data = b"Attack at dawn: 0601"
        orig_file.write_bytes(tampered_data)
        hash_tampered = calculate_file_sha256(orig_file)

        assert hash_orig != hash_tampered

        # Verify avalanche effect on this 1-byte change
        avalanche = compute_avalanche_effect(orig_data.decode(), tampered_data.decode())
        assert avalanche["differing_bits"] > 80  # Significant bit flip observed

    def test_appended_content_detection(self, tmp_path: Path):
        """4. Detection of appended content (e.g. trailing newline or space)."""
        file_path = tmp_path / "append_test.txt"
        file_path.write_text("Baseline content", encoding="utf-8")
        hash_before = calculate_file_sha256(file_path)

        # Append a single space
        with open(file_path, "a", encoding="utf-8") as f:
            f.write(" ")

        hash_after = calculate_file_sha256(file_path)
        assert hash_before != hash_after

    def test_missing_file_handling(self, tmp_path: Path):
        """6. Handling of missing files must raise FileNotFoundError."""
        non_existent = tmp_path / "does_not_exist.txt"
        with pytest.raises(FileNotFoundError):
            calculate_file_sha256(non_existent)

    def test_directory_handling(self, tmp_path: Path):
        """Handling of directory instead of file must raise IsADirectoryError."""
        sub_dir = tmp_path / "sub_directory"
        sub_dir.mkdir()
        with pytest.raises(IsADirectoryError):
            calculate_file_sha256(sub_dir)

    def test_avalanche_effect_computation(self):
        """Tests Hamming distance and avalanche effect computation."""
        res = compute_avalanche_effect("Hello World", "Hello world")
        assert res["differing_bits"] > 50
        assert 0.0 < res["percentage_difference"] < 100.0
