"""
hashing.py - Cryptographic Hashing Module using SHA-256
Part of 'Secure File Integrity Verification Using SHA-256'
Subject: Cryptography and Network Security

This module handles SHA-256 cryptographic hash computation for files and strings.
Files are processed in fixed chunks (default 64 KB) to ensure constant memory
consumption regardless of file size (O(1) memory complexity).
"""

import hashlib
import logging
from pathlib import Path
from typing import Tuple, Optional

logger = logging.getLogger(__name__)

# Standard 64 KB buffer for streaming file reads
DEFAULT_CHUNK_SIZE = 64 * 1024  # 65,536 bytes

# Standard SHA-256 digest of an empty input (for verification & reference)
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


class HashingError(Exception):
    """Custom exception raised when file hashing fails."""
    pass


def calculate_file_sha256(
    file_path: str | Path,
    chunk_size: int = DEFAULT_CHUNK_SIZE
) -> str:
    """
    Computes the SHA-256 cryptographic hash for a file on disk.

    Args:
        file_path: Path to the target file.
        chunk_size: Number of bytes to read per iteration (default: 64 KB).

    Returns:
        Hexadecimal string digest of the SHA-256 hash (64 characters).

    Raises:
        FileNotFoundError: If the target file does not exist.
        PermissionError: If read permissions are denied.
        IsADirectoryError: If the path is a directory instead of a file.
        HashingError: For any other unhandled I/O or hashing error.
    """
    path = Path(file_path).resolve()

    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    if path.is_dir():
        raise IsADirectoryError(f"Path is a directory, not a file: {path}")

    sha256 = hashlib.sha256()

    try:
        with open(path, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                sha256.update(chunk)
    except PermissionError as e:
        logger.error(f"Permission denied while reading {path}: {e}")
        raise PermissionError(f"Permission denied reading file: {path}") from e
    except OSError as e:
        logger.error(f"OS error reading {path}: {e}")
        raise HashingError(f"Failed to read file {path}: {e}") from e

    digest = sha256.hexdigest().lower()
    logger.debug(f"Computed SHA-256 for {path.name}: {digest}")
    return digest


def calculate_string_sha256(text: str, encoding: str = "utf-8") -> str:
    """
    Computes the SHA-256 digest of a text string.

    Args:
        text: String input.
        encoding: Character encoding (default: utf-8).

    Returns:
        64-character lowercase hex digest.
    """
    return hashlib.sha256(text.encode(encoding)).hexdigest().lower()


def calculate_bytes_sha256(data: bytes) -> str:
    """
    Computes the SHA-256 digest of raw byte data.

    Args:
        data: Bytes to hash.

    Returns:
        64-character lowercase hex digest.
    """
    return hashlib.sha256(data).hexdigest().lower()


def compute_avalanche_effect(text1: str, text2: str) -> dict:
    """
    Demonstrates the Avalanche Effect of SHA-256 by comparing hashes of two inputs.
    In a strong cryptographic hash function, changing a single bit in the input
    should change approximately 50% of the output bits on average.

    Returns:
        Dictionary containing digests, bit differences, and percentage flipped.
    """
    hash1 = calculate_string_sha256(text1)
    hash2 = calculate_string_sha256(text2)

    # Convert hex digests to 256-bit binary strings
    bin1 = bin(int(hash1, 16))[2:].zfill(256)
    bin2 = bin(int(hash2, 16))[2:].zfill(256)

    # Count differing bits (Hamming Distance)
    bit_differences = sum(b1 != b2 for b1, b2 in zip(bin1, bin2))
    percentage = (bit_differences / 256.0) * 100.0

    return {
        "input1": text1,
        "input2": text2,
        "hash1": hash1,
        "hash2": hash2,
        "differing_bits": bit_differences,
        "total_bits": 256,
        "percentage_difference": round(percentage, 2)
    }
