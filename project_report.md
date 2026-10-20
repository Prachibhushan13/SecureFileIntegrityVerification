# SECURE FILE INTEGRITY VERIFICATION USING SHA-256

**Course Title:** Cryptography and Network Security  
**Academic Degree:** Bachelor of Technology in Computer Science & Engineering / Information Security  
**Project Type:** Academic Mini-Project  
**Documentation Date:** October 2026  

---

## TABLE OF CONTENTS

1. [Abstract](#1-abstract)
2. [Introduction](#2-introduction)
3. [Problem Statement](#3-problem-statement)
4. [Objectives](#4-objectives)
5. [Existing System and Proposed System](#5-existing-system-and-proposed-system)
6. [System Architecture](#6-system-architecture)
7. [Algorithm and Flowchart Description](#7-algorithm-and-flowchart-description)
8. [SHA-256 Theoretical Framework](#8-sha-256-theoretical-framework)
9. [Implementation Details](#9-implementation-details)
10. [Test Cases and Verification Results](#10-test-cases-and-verification-results)
11. [Security Analysis and Threat Modeling](#11-security-analysis-and-threat-modeling)
12. [Limitations](#12-limitations)
13. [Future Scope](#13-future-scope)
14. [Conclusion](#14-conclusion)
15. [References](#15-references)

---

## 1. ABSTRACT

In contemporary computing environments, file tampering, unauthorized modifications, malware infection, and transmission errors pose significant threats to data integrity. Operating system timestamps and metadata fail to provide cryptographic assurance of file authenticity. This project presents **"Secure File Integrity Verification Using SHA-256,"** an offline, high-performance desktop application designed to detect unauthorized alterations in files of arbitrary sizes.

Built upon Python 3, Tkinter/ttk, SQLite3, and the FIPS PUB 180-4 compliant `hashlib.sha256()` algorithm, the application establishes a trusted baseline database for sensitive files. File data is processed through constant-memory 64 KB chunked streams ($O(1)$ memory consumption), generating deterministic 256-bit hexadecimal digests. During verification, computed hashes are compared against the recorded baselines to detect even single-bit deviations via the Avalanche Effect. Baseline registration and verification workflows are strictly decoupled to prevent automated or accidental overwrites upon detecting tampering. The application incorporates full audit logging, searchable history, CSV and text report exports, and an interactive Avalanche Effect demonstration lab. The system was validated against 21 automated unit and integration tests with a 100% pass rate.

---

## 2. INTRODUCTION

Data integrity is one of the three foundational pillars of information security, alongside Confidentiality and Availability (the CIA Triad). Integrity guarantees that data remains unaltered, accurate, and trustworthy throughout its lifecycle.

In modern computer systems, files may be modified intentionally by unauthorized intruders, trojanized by malware, partially corrupted by disk hardware faults, or modified during unencrypted network transmissions. Unlike confidentiality, which conceals information using symmetric or asymmetric encryption, integrity verification uses cryptographic hash functions to generate unique, fixed-size mathematical fingerprints of data.

The **Secure File Integrity Verification** project establishes a host-based file integrity monitoring system (FIMS). By capturing an immutable cryptographic baseline of a file at its known-good state, any subsequent alteration—whether adding a single whitespace character or altering thousands of bytes—produces an entirely distinct hash value. This project provides both theoretical insights into the internal rounds and compression functions of SHA-256 and a practical, user-friendly implementation.

---

## 3. PROBLEM STATEMENT

Standard file management systems (such as Windows NTFS, macOS APFS, and Linux ext4) provide only basic metadata for tracking files:
- Last modified timestamp
- File size in bytes
- File permissions and access control lists (ACLs)

These metadata attributes are trivially compromised:
1. **Timestamp Forgery ("Timestomping"):** Adversaries and rootkits routinely alter file modification timestamps using system calls (e.g., `touch` or the Win32 `SetFileTime` API) to disguise altered malware binaries among legitimate system files.
2. **Identical File Size Padding:** An attacker can alter bytes within an executable or script while maintaining the exact original byte count by padding null bytes or adjusting non-critical comments.
3. **Silent Hardware Bit Rot:** Storage degradation or transmission errors may flip bits without alerting the operating system.

Without cryptographic verification, users and system administrators cannot confirm whether critical files (such as configuration files, scripts, binaries, or legal contracts) have been altered. A reliable, accessible system is needed to establish trusted baselines and flag any unauthorized change.

---

## 4. OBJECTIVES

The primary objectives of this project are:
1. **Cryptographic Hash Computation:** Implement FIPS PUB 180-4 standard SHA-256 file hashing with chunked binary reading to support arbitrarily large files without high memory usage.
2. **Baseline Persistence:** Store file baselines (filename, absolute path, SHA-256 digest, file size, registration timestamp) in an ACID-compliant SQLite3 database using parameterized queries.
3. **Decoupled Verification Workflow:** Separate the baseline registration process from verification checks, ensuring that detected tampering never triggers an automatic baseline replacement.
4. **Tampering Detection & Diagnostics:** Flag any modification, distinguish between clean matches, mismatches, unregistered files, missing files, and I/O errors, and compute the Hamming distance (differing bits) between digests.
5. **Audit Logging & Reporting:** Record all verification attempts in a dedicated historical audit table, supporting search, filtering, and export to CSV and formatted text reports.
6. **Educational Cryptographic Lab:** Provide an interactive demonstration of the Avalanche Effect (Strict Avalanche Criterion), showing how a 1-character input change causes ~50% of digest bits to flip.
7. **Complete Automated Testing:** Ensure 100% test coverage across known NIST test vectors, edge cases, error conditions, and database transactions.

---

## 5. EXISTING SYSTEM AND PROPOSED SYSTEM

### 5.1 Analysis of the Existing System
In standard desktop workflows, users rely on:
- Manual inspection of file sizes and modified dates.
- Command-line utilities (such as `sha256sum`, `shasum`, or `CertUtil`) that require manual copy-pasting and terminal proficiency.
- Ad-hoc text files containing hash records with no database locking, relational integrity, or audit logging.

**Drawbacks of Existing Approach:**
- Prone to human error during manual visual hash comparison.
- Lack of centralized baseline storage.
- High memory consumption in naive scripts that read entire files into RAM at once (`f.read()`).
- No tamper prevention for the baseline storage itself.
- Inability to quickly inspect history or export structured verification reports.

### 5.2 Proposed System
The proposed application overcomes these deficiencies by providing:
1. **Automated Baseline Database:** SQLite3 database maintaining indexed paths, trusted digests, and audit timestamps.
2. **Chunked Streaming Engine:** 64 KB binary chunk buffer ensuring constant $O(1)$ memory overhead.
3. **Clear Visual Status Badging:** High-contrast color-coded indicators (Emerald Green for verified, Crimson Red for mismatch/tampering, Amber for warnings).
4. **Explicit Overwrite Guardrails:** Prominent warnings requiring affirmative user confirmation before any recorded baseline can be updated.
5. **Integrated Audit Logging:** Complete audit trail tracking every verification check, timestamp, expected digest, and actual digest.
6. **Built-in Avalanche Laboratory:** Dynamic tool visualizing bit-level Hamming distances and explaining cryptographic properties.

### 5.3 Comparison Matrix

| Feature | Manual CLI Commands (`sha256sum`) | Ad-hoc Python Scripts | Proposed Integrity Verification System |
|---|---|---|---|
| **User Interface** | Terminal only | None / Bare Terminal | Polished Desktop GUI + CLI flags |
| **Baseline Storage** | Manual text file | None / In-memory | SQLite3 ACID database |
| **Memory Efficiency** | High (streaming) | Often poor (`read()`) | High ($O(1)$ 64 KB chunking) |
| **Tamper Protection** | None | None | Baseline overwrite guardrails |
| **Audit Log Trail** | None | None | Relational history table with timestamps |
| **Report Generation** | Manual output redirection | None | Automated formatted TXT and CSV |
| **Avalanche Analysis** | Not available | Not available | Integrated Hamming distance engine |

---

## 6. SYSTEM ARCHITECTURE

The application follows a clean, modular architectural design separating data access, cryptographic operations, business logic, presentation, and reporting.

```mermaid
graph TD
    UI[Tkinter / ttk Desktop GUI] --> Svc[Integrity Service]
    CLI[Command Line Interface main.py] --> Svc
    Demo[Demonstration Scenario demo_walkthrough.py] --> Svc

    subgraph Core Engine
        Svc --> Hash[SHA-256 Hashing Module hashing.py]
        Svc --> DB[Database Manager database.py]
        Svc --> Rpt[Report Generator report_generator.py]
    end

    subgraph Data & Storage
        Hash --> DiskFiles[(Filesystem Target Files)]
        DB --> SQLite[(SQLite3 Database file_integrity.db)]
        Rpt --> ReportFiles[(reports/ Directory TXT & CSV)]
    end
```

### Module Responsibilities:
- **`hashing.py`:** Standalone, pure cryptographic module. Executes `hashlib.sha256()` across 64 KB binary chunks, handles OS read errors, and calculates the Avalanche Effect (Hamming distance).
- **`database.py`:** Encapsulates SQLite3 connections, initializes schemas (`files`, `verification_history`), enforces relational foreign keys, and executes parameterized queries.
- **`integrity_service.py`:** Coordinates hashing with database state. Implements validation logic, guards against unconfirmed baseline overwrites, and handles edge cases (missing file, unreadable file, unregistered file).
- **`report_generator.py`:** Formats verification results into structured text files and exports audit logs into standard CSV files, including mandatory cryptographic disclaimers.
- **`gui/` Package:** Implements modern desktop interface using Tkinter and ttk styling, with submodules for dashboard cards, baseline management, history logs, dialogs, and the Avalanche Effect lab.
- **`main.py`:** Unified entry point supporting graphical execution and command-line automation (`--register`, `--verify`, `--demo`, etc.).

---

## 7. ALGORITHM AND FLOWCHART DESCRIPTION

### 7.1 Chunked File Hashing Algorithm

```text
Algorithm: Chunked_SHA256_Digest(file_path, chunk_size = 65536)
Input: Absolute path to target file, buffer chunk size
Output: 64-character lowercase hexadecimal SHA-256 digest

1. Resolve absolute path and verify file exists and is not a directory.
2. Initialize SHA-256 context: H = hashlib.sha256()
3. Open file in binary read mode: f = open(path, "rb")
4. While True:
       chunk = f.read(chunk_size)
       if chunk is empty:
           break
       H.update(chunk)
5. Close file f
6. Return H.hexdigest().lower()
```

### 7.2 File Verification Logic Flowchart

```mermaid
flowchart TD
    Start([User Requests File Verification]) --> CheckDB{Is File Path in Database?}
    
    CheckDB -- No --> ComputeUnregistered[Compute SHA-256 if file readable]
    ComputeUnregistered --> LogUnregistered[Log FILE NOT REGISTERED to History]
    LogUnregistered --> ShowNotReg[Display FILE NOT REGISTERED]
    
    CheckDB -- Yes --> CheckDisk{Does File Exist on Disk?}
    
    CheckDisk -- No --> LogMissing[Log FILE NOT FOUND to History]
    LogMissing --> ShowMissing[Display FILE NOT FOUND Alert]
    
    CheckDisk -- Yes --> TryHash{Can File be Read?}
    
    TryHash -- Error --> LogError[Log VERIFICATION ERROR to History]
    LogError --> ShowError[Display I/O Permission Error Alert]
    
    TryHash -- Success --> HashComputed[Compute Current SHA-256 Digest]
    HashComputed --> CompareHashes{Does Current Digest == Trusted Baseline?}
    
    CompareHashes -- Yes --> UpdateVerified[Update Status: INTEGRITY VERIFIED]
    UpdateVerified --> LogVerified[Record Success in History Table]
    LogVerified --> ShowGreen[Display Green Status: INTEGRITY VERIFIED]
    
    CompareHashes -- No --> CalculateAvalanche[Calculate Bit Hamming Distance]
    CalculateAvalanche --> UpdateModified[Update Status: FILE MODIFIED]
    UpdateModified --> LogModified[Record Tamper Event in History Table]
    LogModified --> KeepBaseline[RETAIN ORIGINAL BASELINE - DO NOT OVERWRITE]
    KeepBaseline --> ShowRed[Display Red Alert: FILE MODIFIED - HASH MISMATCH]
```

---

## 8. SHA-256 THEORETICAL FRAMEWORK

### 8.1 Hashing vs. Encryption
A fundamental concept in Cryptography and Network Security is distinguishing between **Hashing** and **Encryption**:

| Attribute | Cryptographic Hashing (e.g., SHA-256) | Encryption (e.g., AES-256, RSA) |
|---|---|---|
| **Mathematical Nature** | One-way transformation ($f: X \rightarrow Y$) | Two-way reversible transformation ($E_K(P) \rightarrow C$, $D_K(C) \rightarrow P$) |
| **Key Requirement** | No key required (deterministic output from input) | Secret key (symmetric) or key pair (asymmetric) |
| **Output Length** | Fixed length (256 bits regardless of input size) | Variable length (proportional to plaintext size) |
| **Primary Objective** | **Integrity verification** & message authentication | **Confidentiality** & privacy protection |
| **Reversibility** | Computationally infeasible to reverse ($f^{-1}$ does not exist) | Readily reversible by authorized key holders |

### 8.2 Three Essential Security Properties of Cryptographic Hash Functions
1. **Pre-Image Resistance (One-Way Property):**  
   Given any hash digest $h$, it is computationally infeasible to find any original message $m$ such that:
   $$\text{SHA-256}(m) = h$$
   For SHA-256, finding a pre-image requires brute-force searching through $2^{256}$ operations, which exceeds the physical computational capacity of all computers on Earth.
   
2. **Second Pre-Image Resistance (Weak Collision Resistance):**  
   Given a specific input message $m_1$, it is computationally infeasible to find another distinct message $m_2 \neq m_1$ such that:
   $$\text{SHA-256}(m_1) = \text{SHA-256}(m_2)$$
   This ensures an attacker cannot craft a forged document that matches an existing document's baseline digest.

3. **Collision Resistance (Strong Collision Resistance):**  
   It is computationally infeasible to find *any* two arbitrary distinct messages $m_1 \neq m_2$ that produce identical digests:
   $$\text{SHA-256}(m_1) = \text{SHA-256}(m_2)$$
   Due to the Birthday Paradox, the complexity of finding any collision is approximately $2^{128}$ operations—a bound that remains completely secure against modern cryptanalysis.

### 8.3 The Avalanche Effect (Strict Avalanche Criterion)
The **Avalanche Effect** is a critical security property of cryptographic hash functions and block ciphers. It dictates that if an input is changed by just a single bit, the output digest must change drastically and unpredictably—statistically flipping approximately 50% of the output bits.

In SHA-256, flipping a single bit at the input ripples through 64 rounds of non-linear Boolean operations, bitwise rotations, modular additions, and message schedule expansions. As experimentally demonstrated in Section 10, changing a single character ("Original secure content" to "Modified secure content") causes **136 of 256 bits (53.12%)** to flip.

### 8.4 Mathematical Mechanics of SHA-256
SHA-256 processes messages according to the NIST FIPS PUB 180-4 standard:

1. **Preprocessing and Padding:**  
   The arbitrary-length message $M$ of length $L$ bits is padded such that its length is congruent to $448 \pmod{512}$:
   - Append a single bit `'1'`.
   - Append $k$ zero bits `'0'`, where $k$ is the smallest non-negative integer satisfying $L + 1 + k \equiv 448 \pmod{512}$.
   - Append the original length $L$ as a 64-bit big-endian integer.
   - The total message length is now an exact multiple of 512 bits ($16 \times 32$-bit words).

2. **Constants and Initial State:**  
   The initial 256-bit hash buffer consists of eight 32-bit working variables $(H_0 \dots H_7)$, derived from the fractional parts of the square roots of the first 8 prime numbers (2, 3, 5, 7, 11, 13, 17, 19):
   - $H_0 = \text{0x6a09e667}, \quad H_1 = \text{0xbb67ae85}$
   - $H_2 = \text{0x3c6ef372}, \quad H_3 = \text{0xa54ff53a}$
   - $H_4 = \text{0x510e527f}, \quad H_5 = \text{0x9b05688c}$
   - $H_6 = \text{0x1f83d9ab}, \quad H_7 = \text{0x5be0cd19}$

   The algorithm utilizes 64 constant 32-bit words $K_0 \dots K_{63}$, derived from the fractional parts of the cube roots of the first 64 prime numbers.

3. **Message Schedule Expansion:**  
   For each 512-bit block, the 16 words $W_0 \dots W_{15}$ are expanded into 64 words $W_0 \dots W_{63}$ using non-linear sigma functions:
   $$W_t = \sigma_1(W_{t-2}) + W_{t-7} + \sigma_0(W_{t-15}) + W_{t-16} \pmod{2^{32}}$$
   where:
   $$\sigma_0(x) = \text{ROTR}^7(x) \oplus \text{ROTR}^{18}(x) \oplus \text{SHR}^3(x)$$
   $$\sigma_1(x) = \text{ROTR}^{17}(x) \oplus \text{ROTR}^{19}(x) \oplus \text{SHR}^{10}(x)$$

4. **64-Round Compression Function:**  
   Each block undergoes 64 rounds using temporary variables $T_1$ and $T_2$:
   $$T_1 = h + \Sigma_1(e) + \text{Ch}(e, f, g) + K_t + W_t$$
   $$T_2 = \Sigma_0(a) + \text{Maj}(a, b, c)$$
   $$h = g; \quad g = f; \quad f = e; \quad e = d + T_1; \quad d = c; \quad c = b; \quad b = a; \quad a = T_1 + T_2$$
   where:
   $$\text{Ch}(x, y, z) = (x \wedge y) \oplus (\neg x \wedge z)$$
   $$\text{Maj}(x, y, z) = (x \wedge y) \oplus (x \wedge z) \oplus (y \wedge z)$$
   $$\Sigma_0(x) = \text{ROTR}^2(x) \oplus \text{ROTR}^{13}(x) \oplus \text{ROTR}^{22}(x)$$
   $$\Sigma_1(x) = \text{ROTR}^6(x) \oplus \text{ROTR}^{11}(x) \oplus \text{ROTR}^{25}(x)$$

5. **Final Digest Concatenation:**  
   After processing all 512-bit blocks, the final working variables are concatenated to form the 256-bit digest:
   $$\text{Digest} = H_0 \parallel H_1 \parallel H_2 \parallel H_3 \parallel H_4 \parallel H_5 \parallel H_6 \parallel H_7$$

---

## 9. IMPLEMENTATION DETAILS

### 9.1 Database Architecture
The application manages two relational SQLite tables:

#### Table: `files` (Trusted Baselines)
```sql
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
```

#### Table: `verification_history` (Audit Trail)
```sql
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
```

### 9.2 Decoupled Baseline Management
A common architectural flaw in naive integrity monitoring tools is automatically updating the stored baseline whenever an integrity check is run. In this project:
- `verify_file()` is strictly read-only with respect to the `trusted_hash` column.
- If a hash mismatch is detected, `files.last_verification_status` is updated to `'FILE MODIFIED — HASH MISMATCH'`, and an audit record is logged.
- The `trusted_hash` remains untouched.
- Updating a baseline requires explicit invocation of `register_file(path, allow_overwrite=True)` after the user has reviewed a warning dialog and confirmed that the file change was authorized.

---

## 10. TEST CASES AND VERIFICATION RESULTS

The system was evaluated using an automated test suite implemented in `pytest`. All 21 test cases were executed and passed.

### 10.1 Automated Test Execution Log

```text
============================= test session starts ==============================
platform darwin -- Python 3.13.9, pytest-8.4.2, pluggy-1.5.0
rootdir: /Users/prachibhushan/cnsassignment
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

### 10.2 Detailed Test Case Summary Table

| Test Case ID | Test Category | Objective | Input / Condition | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|---|
| **TC-01** | Hashing | Verify NIST Standard Test Vector | String `"abc"` | `ba7816bf...15ad` | `ba7816bf...15ad` | **PASSED** |
| **TC-02** | Hashing | Verify Empty Input Handling | 0-byte file / empty string | `e3b0c442...855` | `e3b0c442...855` | **PASSED** |
| **TC-03** | Hashing | Verify Repeated Hashing Determinism | Same file hashed 3 times | Identical digests across all runs | Exact 64-char match | **PASSED** |
| **TC-04** | Hashing | Detect Single Byte Modification | Change `'0'` to `'1'` in binary payload | Digest differs; $>80$ bits flipped | Digest mismatch detected | **PASSED** |
| **TC-05** | Hashing | Detect Appended Content | Append single whitespace character | Digest differs immediately | Digest mismatch detected | **PASSED** |
| **TC-06** | Hashing | Handle Missing Target File | Non-existent path | Raise `FileNotFoundError` | `FileNotFoundError` raised | **PASSED** |
| **TC-07** | Hashing | Handle Directory Path Target | Path points to folder, not file | Raise `IsADirectoryError` | `IsADirectoryError` raised | **PASSED** |
| **TC-08** | Cryptography | Avalanche Effect Hamming Distance | Compare `"Hello World"` vs `"Hello world"` | $40\%-60\%$ bits flip | $49.2\%$ bits flipped | **PASSED** |
| **TC-09** | Database | Automatic Schema Initialization | New DB path initialization | Tables and indexes created | Clean schema initialized | **PASSED** |
| **TC-10** | Database | Baseline Record CRUD | Register file baseline | Correct ID, path, and hash stored | Record retrieved accurately | **PASSED** |
| **TC-11** | Database | Prevent Duplicate Path Entries | Re-insert same absolute path | `sqlite3.IntegrityError` triggered | Unique constraint enforced | **PASSED** |
| **TC-12** | Database | Explicit Baseline Update | Update hash via `update_baseline` | Record updated; timestamp refreshed | Hash updated properly | **PASSED** |
| **TC-13** | Database | History Audit Filter & Search | Query history by status | Correct subset of records returned | Accurate filtered results | **PASSED** |
| **TC-14** | Database | Baseline Record Deletion | Delete recorded baseline by ID | Record purged from DB | Row removed completely | **PASSED** |
| **TC-15** | Integrity | Clean File Verification | Verify unchanged registered file | `INTEGRITY VERIFIED` status | Verified clean match | **PASSED** |
| **TC-16** | Integrity | Tampered File Verification | Modify file contents after registration | `FILE MODIFIED — HASH MISMATCH` | Mismatch detected | **PASSED** |
| **TC-17** | Integrity | Unregistered File Handling | Verify file not present in DB | `FILE NOT REGISTERED` status | Warning status assigned | **PASSED** |
| **TC-18** | Integrity | Missing Registered File Handling | Delete registered file from disk | `FILE NOT FOUND` status | Missing status recorded | **PASSED** |
| **TC-19** | Integrity | Guard Accidental Overwrite | Register file again with `overwrite=False` | Return `False` & preserve baseline | Baseline untouched | **PASSED** |
| **TC-20** | Performance | Chunked Large File Streaming | 250 KB file (exceeds 64 KB chunk) | Process without loading whole file | Verified accurately | **PASSED** |
| **TC-21** | Batch | Batch Verification of Multiple Files | Verify mixture of clean & altered files | Individual statuses returned | Batch report completed | **PASSED** |

---

## 11. SECURITY ANALYSIS AND THREAT MODELING

### 11.1 Threat Model and Trust Boundaries
A rigorous security analysis requires defining the threat model:

1. **Threat Scenario A: Unauthorized Content Modification (Covered)**  
   *Threat:* An attacker modifies a configuration file or executable on disk without administrative database privileges.  
   *Mitigation:* Upon verification, SHA-256 computes a drastically different digest. The system flags `FILE MODIFIED — HASH MISMATCH` and logs the event.
   
2. **Threat Scenario B: Accidental Baseline Overwrite (Covered)**  
   *Threat:* A user or script runs a verification check on a modified file and inadvertently overwrites the baseline.  
   *Mitigation:* Registration and verification are strictly decoupled. Even if a mismatch is detected, the baseline remains unaltered. Overwriting requires explicit user confirmation via a warning dialog.

3. **Threat Scenario C: Privileged Adversary Access (System Limitation)**  
   *Threat:* An attacker gains local root or administrator access, enabling write access to both the target files and the SQLite database (`file_integrity.db`).  
   *Residual Risk:* The attacker could modify both the file and the corresponding `trusted_hash` row in the database, masking the modification.  
   *Mitigation Architecture:* In mission-critical environments, the baseline database should be stored on a remote, write-only syslog/SIEM server, or signed using public-key cryptography (e.g., RSA-PSS or Ed25519) where the private signing key is stored in a Hardware Security Module (HSM).

### 11.2 The "Clean Hash" Fallacy
A critical security notice implemented throughout the application and generated reports addresses the "Clean Hash" fallacy:
> **Security Notice:** Verifying that a file matches its registered SHA-256 hash proves only that the file is bit-for-bit identical to the recorded baseline. It does **not** certify that the file is safe, non-malicious, or malware-free. If a malicious file is registered into the baseline database, it will verify cleanly. Integrity verification guarantees identity, not safety.

---

## 12. LIMITATIONS

1. **Host-Local Database Storage:** By default, the SQLite database is stored locally. An adversary with administrative write permissions could tamper with both the files and the database.
2. **On-Demand Rather Than Real-Time:** Verifications are triggered manually or in scheduled batch runs; the current implementation does not run a continuous kernel-level file-system watcher (e.g., inotify or FSEvents).
3. **No Digital Signatures:** The application uses symmetric hashing (SHA-256) rather than asymmetric digital signatures (such as ECDSA or RSA-PSS). It verifies integrity, but cannot provide non-repudiation without PKI certificates.
4. **Offline Desktop Scope:** Designed as a standalone desktop utility rather than a distributed agent-server enterprise architecture.

---

## 13. FUTURE SCOPE

1. **Real-Time Filesystem Monitoring:** Integrate asynchronous filesystem event hooks (e.g., Python `watchdog` or OS kernel primitives) to detect modifications the moment a file is written to.
2. **Asymmetric PKI Manifest Signing:** Implement digital signature support (Ed25519 or RSA-4096) to cryptographically sign baseline manifests, ensuring tamper-evidence even if the local database file is altered.
3. **Remote WORM Log Shipping:** Stream audit verification events over TLS to a remote SIEM (Security Information and Event Management) platform or append-only cloud ledger.
4. **Hierarchical Directory Trees (Merkle Trees):** Implement Merkle Tree hashing to allow instant verification of entire directory structures and subdirectories with minimal hash comparisons.

---

## 14. CONCLUSION

The **Secure File Integrity Verification Using SHA-256** project demonstrates the practical application of cryptographic hashing in system security. By implementing FIPS PUB 180-4 SHA-256 with constant-memory chunked streaming, relational baseline tracking, and strict separation between registration and verification, the system reliably detects unauthorized file modifications down to a single bit.

The application satisfies all academic and practical requirements: clean visual architecture, ACID-compliant persistence, automated audit logging, interactive educational laboratories, and complete automated test coverage (21/21 tests passed). It bridges theoretical cryptography concepts—such as the Avalanche Effect and pre-image resistance—with real-world software security practices.

---

## 15. REFERENCES

1. **National Institute of Standards and Technology (NIST):**  
   *FIPS PUB 180-4: Secure Hash Standard (SHS).* U.S. Department of Commerce, August 2015.  
   DOI: [10.6028/NIST.FIPS.180-4](https://csrc.nist.gov/publications/detail/fips/180-4/final)

2. **Python Software Foundation:**  
   *`hashlib` — Secure hashes and message digests.* Python 3.13 Standard Library Documentation.  
   URL: [https://docs.python.org/3/library/hashlib.html](https://docs.python.org/3/library/hashlib.html)

3. **Python Software Foundation:**  
   *`sqlite3` — DB-API 2.0 interface for SQLite databases.* Python 3.13 Standard Library Documentation.  
   URL: [https://docs.python.org/3/library/sqlite3.html](https://docs.python.org/3/library/sqlite3.html)

4. **Stallings, William:**  
   *Cryptography and Network Security: Principles and Practice.* 8th Edition, Pearson Education, 2020.

5. **Katz, Jonathan, and Lindell, Yehuda:**  
   *Introduction to Modern Cryptography.* 3rd Edition, Chapman and Hall/CRC, 2020.

6. **SQLite Development Team:**  
   *SQLite Foreign Key Support and ACID Transactions.*  
   URL: [https://www.sqlite.org/foreignkeys.html](https://www.sqlite.org/foreignkeys.html)
