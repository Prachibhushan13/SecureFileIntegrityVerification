# Secure File Integrity Verification Using SHA-256

**Subject:** Cryptography and Network Security (College Mini Project)  
**Academic Level:** Bachelor of Technology / Computer Science & Engineering / Cybersecurity  
**Author:** Pair-programmed with Antigravity  

---

## 1. Project Overview

**Secure File Integrity Verification Using SHA-256** is a desktop cybersecurity application developed in Python. It detects whether a file has been altered, corrupted, or maliciously tampered with by generating a cryptographically secure 256-bit hash baseline and performing verification against stored records in a local SQLite database.

The application adheres to cybersecurity best practices by strictly decoupling file baseline registration from integrity verification, reading files in constant-memory 64 KB streams, providing visual indicators of hash matches and mismatches, analyzing the Avalanche Effect (Hamming distance), and generating structured audit reports.

---

## 2. Problem Statement

In modern networked computer systems, files are routinely exposed to tampering, unauthorized modifications, transmission errors, ransomware modifications, and malicious Trojan injections. Operating systems and standard file explorers display timestamps and file sizes, but both can be forged or may conceal byte-level alterations (such as changing a single character or configuration flag).

Without cryptographic integrity checks, users cannot reliably distinguish an authentic file from a compromised one. A lightweight, offline, and reliable integrity verification system is needed to establish trusted baselines and detect unauthorized modifications immediately.

---

## 3. Project Objectives

1. **Cryptographic Integrity Verification:** Implement the SHA-256 algorithm (FIPS PUB 180-4) using chunked binary reading to generate standard 256-bit hexadecimal digests.
2. **Baseline Management:** Securely record and update trusted file baselines in an ACID-compliant SQLite3 database using parameterized queries.
3. **Tampering Detection:** Accurately identify even a single-bit or single-byte modification in files of any size.
4. **Accidental Overwrite Prevention:** Enforce explicit confirmation protocols so baselines are never silently or automatically replaced upon detecting an integrity mismatch.
5. **Audit History & Reporting:** Maintain complete audit logs of all verification attempts with timestamps, expected vs. actual digests, and exportable text/CSV reports.
6. **Educational Cryptography Demonstrations:** Provide an interactive laboratory tool illustrating the Avalanche Effect, Hamming distance, and key cryptographic properties.

---

## 4. Key Features

- **Modern Desktop Dashboard:** Custom Tkinter/ttk interface with real-time KPI metric cards (Registered Baselines, Clean Verifications, Tampering Detected, Total Audits).
- **Chunked File Streaming:** 64 KB buffer size ensures constant $O(1)$ memory consumption, allowing verification of multi-gigabyte files without memory exhaustion.
- **Strict Baseline Protection:** Mismatched files trigger clear alerts; baselines remain untouched unless the user explicitly authorizes an update.
- **Side-by-Side Digest Comparison:** High-contrast visual comparison of expected vs. actual hashes with one-click clipboard copying.
- **Comprehensive Verification Statuses:**
  - `INTEGRITY VERIFIED` (Green badge / exact match)
  - `FILE MODIFIED — HASH MISMATCH` (Red badge / tamper detected)
  - `FILE NOT REGISTERED` (Amber badge / prompt to create baseline)
  - `FILE NOT FOUND` (Amber badge / file missing from recorded path)
  - `VERIFICATION ERROR` (I/O or permission diagnostics)
- **Searchable & Filterable History:** Dedicated audit log viewer with search, status filtering, and CSV export.
- **Cryptographic Disclaimer Notices:** Clear explanations that hash verification guarantees baseline identity, not inherent immunity from malware.
- **Interactive Avalanche Effect Lab:** Live demonstration calculating the Hamming distance between two inputs to observe the Strict Avalanche Criterion (~50% bit flip).
- **Dual GUI & CLI Modes:** Operable via the desktop GUI or headless command-line interface (`main.py` CLI).

---

## 5. Technology Stack

| Component | Technology | Rationale |
|---|---|---|
| **Language** | Python 3.10+ (tested on Python 3.13) | Standard, portable, robust |
| **GUI Framework** | Tkinter + ttk (ttk styling engine) | Native, cross-platform, zero pip dependencies |
| **Database** | SQLite3 | Embedded, serverless, ACID-compliant, zero external configuration |
| **Cryptography** | `hashlib.sha256()` | Certified NIST FIPS PUB 180-4 standard implementation |
| **File I/O** | `pathlib` + standard binary streams | Safe path resolution and chunked stream reading |
| **Testing** | `pytest` | 21 automated unit and integration tests |
| **Reports** | `csv` & formatted text files | Standard, universally readable export formats |

---

## 6. Project Directory Structure

```text
cnsassignment/
├── main.py                     # Main application entry point (GUI + CLI flags)
├── database.py                 # SQLite database management and parameterized queries
├── hashing.py                  # Chunked SHA-256 computation & Avalanche effect logic
├── integrity_service.py        # Core integrity verification and baseline business rules
├── report_generator.py         # Formatted text report and CSV export generation
├── demo_walkthrough.py         # Automated 9-step demonstration scenario
├── gui/
│   ├── __init__.py             # GUI package marker
│   ├── styles.py               # Color tokens, fonts, and ttk widget styling
│   ├── dashboard.py            # Primary desktop application window and KPI cards
│   ├── history_view.py         # Searchable audit history view & CSV export
│   ├── avalanche_view.py       # Interactive Avalanche Effect educational lab
│   └── dialogs.py              # Verification modals, overwrite warnings, copy utilities
├── tests/
│   ├── __init__.py             # Test suite package marker
│   ├── test_hashing.py         # Tests for hashing, test vectors, 1-byte edits, empty files
│   ├── test_database.py        # Tests for SQLite schema, CRUD, and audit logs
│   └── test_integrity.py       # Tests for end-to-end verification and tamper detection
├── reports/
│   └── .gitkeep                # Directory storing exported integrity audit reports
├── requirements.txt            # Project dependencies (pytest for testing)
├── .gitignore                  # Git ignore rules for Python, SQLite, and caches
├── README.md                   # Complete project documentation and guide
└── project_report.md           # Formal 15-section academic mini-project report
```

---

## 7. Installation and Setup

### Prerequisites
- Python 3.10 or higher installed on Windows, macOS, or Linux.
- Tkinter installed (included by default on macOS and Windows Python distributions).

### Installation Steps

1. Clone or navigate to the project directory:
   ```bash
   cd /path/to/cnsassignment
   ```

2. (Optional) Create and activate a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate   # On Windows: venv\Scripts\activate
   ```

3. Install testing dependencies:
   ```bash
   pip install -r requirements.txt
   ```

---

## 8. How to Run the Application

### A. Launch Desktop GUI Application
Simply run `main.py` without arguments:
```bash
python3 main.py
```
This opens the complete desktop application window featuring:
- Dashboard cards showing real-time baseline counts and tamper statistics.
- File registration and verification controls.
- Registered baseline table.
- Searchable audit logs.
- Interactive Avalanche Effect laboratory.

### B. Command-Line Interface (CLI Mode)
The application can also be operated directly from the terminal:

1. **Register a file baseline:**
   ```bash
   python3 main.py --register confidential_document.txt
   ```

2. **Verify a file's integrity:**
   ```bash
   python3 main.py --verify confidential_document.txt
   ```

3. **Verify all registered files in batch:**
   ```bash
   python3 main.py --verify-all
   ```

4. **List all registered baselines:**
   ```bash
   python3 main.py --list
   ```

5. **View verification audit history:**
   ```bash
   python3 main.py --history
   ```

6. **Run the automated college demonstration scenario:**
   ```bash
   python3 main.py --demo
   # or directly:
   python3 demo_walkthrough.py
   ```

---

## 9. Automated Testing

The project includes an automated test suite comprising 21 unit and integration tests covering:
- NIST SHA-256 standard test vectors ("abc", empty string `e3b0...`).
- Repeated hashing consistency.
- Single-byte modification detection.
- Appended content detection.
- Empty file handling (0 bytes).
- Missing files and directory path errors.
- SQLite schema initialization and duplicate prevention.
- Baseline update authorization checks.
- Tamper detection and Avalanche Effect metrics.
- Unregistered and deleted file handling.
- Large file chunked streaming (64 KB chunks).

To run the complete test suite:
```bash
python3 -m pytest tests -v
```

**Test Execution Output:**
```text
============================= test session starts ==============================
collected 21 items

tests/test_database.py::TestDatabaseModule::test_database_initialization PASSED [  4%]
tests/test_database.py::TestDatabaseModule::test_record_creation_and_retrieval PASSED [  9%]
tests/test_database.py::TestDatabaseModule::test_duplicate_registration_prevention PASSED [ 14%]
tests/test_database.py::TestDatabaseModule::test_update_baseline PASSED  [ 19%]
tests/test_database.py::TestDatabaseModule::test_verification_history_creation_and_filtering PASSED [ 23%]
tests/test_database.py::TestDatabaseModule::test_delete_baseline PASSED  [ 28%]
tests/test_hashing.py::TestHashingModule::test_nist_known_test_vectors PASSED [ 33%]
tests/test_hashing.py::TestHashingModule::test_empty_file_hashing PASSED [ 38%]
tests/test_hashing.py::TestHashingModule::test_repeated_hashing_consistency PASSED [ 42%]
tests/test_hashing.py::TestHashingModule::test_one_byte_modification_detection PASSED [ 47%]
tests/test_hashing.py::TestHashingModule::test_appended_content_detection PASSED [ 52%]
tests/test_hashing.py::TestHashingModule::test_missing_file_handling PASSED [ 57%]
tests/test_hashing.py::TestHashingModule::test_directory_handling PASSED [ 61%]
tests/test_hashing.py::TestHashingModule::test_avalanche_effect_computation PASSED [ 66%]
tests/test_integrity.py::TestIntegrityService::test_successful_registration_and_verification PASSED [ 71%]
tests/test_integrity.py::TestIntegrityService::test_mismatched_hash_detection PASSED [ 76%]
tests/test_integrity.py::TestIntegrityService::test_unregistered_file_verification PASSED [ 80%]
tests/test_integrity.py::TestIntegrityService::test_missing_registered_file_handling PASSED [ 85%]
tests/test_integrity.py::TestIntegrityService::test_prevention_of_accidental_baseline_replacement PASSED [ 90%]
tests/test_integrity.py::TestIntegrityService::test_chunked_reading_large_file PASSED [ 95%]
tests/test_integrity.py::TestIntegrityService::test_batch_verification PASSED [100%]

============================== 21 passed in 0.09s ==============================
```

---

## 10. Sample Demonstration Outputs

### A. Clean File Verification Output (`INTEGRITY VERIFIED`)
```text
======================================================================
INTEGRITY VERIFICATION RESULT: [✓ INTEGRITY VERIFIED]
======================================================================
File Path    : /Users/prachibhushan/cnsassignment/confidential_document.txt
Expected Hash: fe032dae0e0240998af7e8875711630c44b0c485f242a8573d23dec60274cdd9
Actual Hash  : fe032dae0e0240998af7e8875711630c44b0c485f242a8573d23dec60274cdd9
Hash Match   : YES (Bit-for-bit identical)
======================================================================
A verification report has been automatically generated in the reports/ directory.
```

### B. Tampered File Verification Output (`FILE MODIFIED — HASH MISMATCH`)
```text
======================================================================
INTEGRITY VERIFICATION RESULT: [✕ FILE MODIFIED — HASH MISMATCH]
======================================================================
File Path    : /Users/prachibhushan/cnsassignment/confidential_document.txt
Expected Hash: fe032dae0e0240998af7e8875711630c44b0c485f242a8573d23dec60274cdd9
Actual Hash  : 7bda2da43c7e1134140b9f6cfb9dc1ece55badf3e11f17b065fa0a91af952f74
Hash Match   : NO
Avalanche    : 136/256 bits changed (53.12%)
Details      : Hash mismatch detected! Differing bits: 136/256
======================================================================
```

---

## 11. Security Model and Limitations

### Threat Model & Assumptions
1. **Integrity vs. Confidentiality:** SHA-256 is a one-way cryptographic digest function designed for **integrity verification**, not data encryption. It does not conceal plaintext contents.
2. **Local Threat Model:** If an adversary achieves local administrative privileges (`root` or equivalent write privileges) on both the filesystem and the local SQLite database, they can tamper with a file and rewrite its trusted database baseline.
3. **Defense-in-Depth Solution:** For enterprise production deployments, baselines should be protected using:
   - **Digital Signatures (PKI):** Baselines signed with an RSA or ECDSA private key held in an HSM/TPM.
   - **Keyed HMACs:** `HMAC-SHA256` utilizing a secure hardware key.
   - **Remote Append-Only Audit Logs:** Sending baseline updates to a centralized WORM (Write Once, Read Many) log server.

---

## 12. Future Enhancements

- **Real-Time Directory File Watcher:** Implementing a background thread using filesystem notification APIs to alert immediately when monitored files are modified.
- **Digital Signature Integration:** Adding public-key cryptography (RSA-PSS or Ed25519) to sign and verify manifest baselines.
- **Hardware Security Module (HSM) / TPM Support:** Storing HMAC baseline verification keys inside hardware security modules.
- **Recursive Directory Baseline Scanning:** Generating recursive integrity manifests for entire system directory trees.
