# CipherPick — Full Technical Documentation

> **Version:** 2.0 · Cyberpunk-Dark Edition  
> **Interface:** Streamlit Web GUI (`app.py`) + CLI (`main.py`)  
> **Architecture:** Decoupled background OS processes via `runner.py`

---

## Table of Contents
1. [Project Overview](#1-project-overview)
2. [Architecture](#2-architecture)
3. [Category 1 — Attacks](#3-category-1--attacks)
4. [Category 2 — StiganoMessenger](#4-category-2--stiganomessenger)
5. [Category 3 — Digital Forensics](#5-category-3--digital-forensics)
6. [Category 4 — OSINT and Information Gathering](#6-category-4--osint-and-information-gathering)
7. [Category 5 — Cryptographic Engine](#7-category-5--cryptographic-engine)
8. [Core Algorithm Engines](#8-core-algorithm-engines)
9. [Algorithm Complexity Summary Table](#9-algorithm-complexity-summary-table)

---

## 1. Project Overview

CipherPick ("Cipher" + "Pick") is a modular, offensive and defensive security toolkit that bundles multiple cybersecurity disciplines into a single unified interface. It provides:

- **Offensive tools**: SQL injection, phishing, password cracking, MITM interception
- **Steganography**: hiding data inside images and text using bit-manipulation
- **Digital Forensics**: file signature analysis, entropy measurement, string extraction
- **OSINT**: social media username hunting, network port scanning
- **Cryptography**: AES-128, RSA-2048, SHA-256 operations

The GUI is built with Streamlit and uses a **background task manager** (`runner.py`) so all long-running tools (SQLMap, port scans, PDF recovery, username hunting) persist even when the user navigates between pages.

---

## 2. Architecture

```
CipherPick/
├── app.py                  # Streamlit GUI (all screens + task manager)
├── main.py                 # CLI entry point (menu-driven)
├── runner.py               # Background subprocess wrapper
├── engine.py               # Cryptographic engine (AES, RSA, SHA-256)
├── core/
│   ├── attack_base.py      # Abstract base class for all attack strategies
│   ├── greedy_engine.py    # Reusable Greedy algorithm engine
│   └── recursion_engine.py # Reusable DFS/backtrack/traverse engine
└── modules/
    ├── password_cracker/   # All password attack strategies
    ├── stegano/            # Image and text steganography
    ├── forensics/          # File investigation tools
    ├── osint/              # Username hunter, OSINT crawlers
    ├── scanner/            # Port scanner (Phase 1 + Phase 2 Nmap)
    ├── sqlmap-master/      # SQLMap (external tool, bundled)
    └── mitm/               # ARP poisoner utilities
```

### Background Task Manager (runner.py)
When the user starts a tool in the GUI, `app.py` spawns a **detached OS process**:
```python
subprocess.Popen([sys.executable, "-u", "runner.py", "TaskType", json_kwargs],
                 stdout=log_file, stderr=subprocess.STDOUT, env={PYTHONUNBUFFERED:1})
```
- Output is piped line-by-line to `.cipherpick_logs/<task_id>.log`
- The GUI tails the log file every 0.15 seconds and streams it into the terminal widget
- The process survives page navigation because it is an **independent OS process**

---

## 3. Category 1 — Attacks

### 3.1 PDF Password Recovery
**File:** `runner.py` → `modules/password_cracker/` (via GUI) or advanced cracker tools (via CLI)

**Usage:**
- GUI: Enter PDF file path + wordlist path → task runs in background
- CLI: Select from numeric / mask / dictionary / hash / frequency sub-attacks

**How it works:**  
Iterates through password candidates and calls `pikepdf.open(pdf_path, password=guess)`. Success = PDF opens without `PasswordError`.

---

#### 3.1.1 Numeric Attack
**File:** `modules/password_cracker/numeric_attack.py`

Systematically tries every numeric combination from `000...0` to `999...9` for a fixed digit-length.

```
Algorithm:  Pure Brute Force (exhaustive enumeration)
Loop:       for i in range(10^length) → try f"{i:0{length}d}"
```

| Metric | Value |
|--------|-------|
| **Time Complexity** | O(10^n) — where n = digit length |
| **Space Complexity** | O(1) — single variable, no storage |
| **Worst Case** | 10^n iterations (password is last or not present) |
| **Best Case** | O(1) — password is "000…0" |

---

#### 3.1.2 Mask Attack
**File:** `modules/password_cracker/mask_attack.py`

Uses a **recursive backtracking** algorithm. The mask pattern defines which positions are digits (`?d`) or lowercase letters (`?l`), and the algorithm exhaustively expands all combinations.

```
Algorithm:  Recursive Backtracking (Constrained Brute Force)
Function:   _backtrack(current_guess, index)
Branching:  For each ?d → 10 branches; for each ?l → 26 branches
```

| Metric | Value |
|--------|-------|
| **Time Complexity** | O(C^p) — C = charset size per token, p = mask positions |
| **Space Complexity** | O(p) — recursion depth = mask length |
| **Example** | Mask `?d?d?d?d` → 10^4 = 10,000 combinations |

---

#### 3.1.3 Trie Dictionary Attack
**File:** `modules/password_cracker/trie_dictionary_attack.py`

Builds a **Trie (Prefix Tree)** from the wordlist, then traverses it with **Depth-First Search (DFS)**, yielding mutations (`word`, `word123`, `word!`) at each end-node.

```
Algorithm:  Trie construction + DFS traversal with mutations
Insert:     O(L) per word, L = word length
Traverse:   DFS via generator (yield from)
```

| Metric | Value |
|--------|-------|
| **Trie Build Time** | O(W × L) — W = words, L = avg word length |
| **Trie Space** | O(W × L) — each character is a node |
| **Traversal Time** | O(W × L) — visits every node once |
| **Advantage** | Prefix sharing → memory-efficient for large wordlists |

---

#### 3.1.4 Hash Cracker
**File:** `modules/password_cracker/hash_cracker.py`

Pre-computes a **hash map** (dictionary) of `{MD5/SHA-256(word) → word}` for every entry in the wordlist, then performs a **single O(1) dictionary lookup** for the target hash.

```
Algorithm:  Pre-computation + O(1) Hash Map Lookup
Phase 1:    Build map → O(W) hashing operations
Phase 2:    target_hash in hash_map → O(1)
```

| Metric | Value |
|--------|-------|
| **Pre-computation Time** | O(W) — W = number of words in wordlist |
| **Lookup Time** | O(1) — Python `dict` is a hash table |
| **Space Complexity** | O(W) — stores all hash→word pairs |

---

#### 3.1.5 Frequency Analyzer (Caesar Cipher Breaker)
**File:** `modules/password_cracker/frequency_analyzer.py`

Uses **Chi-Squared (χ²) statistical analysis** to break Caesar cipher encryption without knowing the shift. Tries all 25 possible shifts and scores each against known English letter frequencies.

```
Algorithm:  Chi-Squared Statistical Scoring over all shifts
χ² = Σ ((observed - expected)² / expected)
Best shift = argmin(χ²)
```

| Metric | Value |
|--------|-------|
| **Time Complexity** | O(25 × N) ≈ O(N) — N = ciphertext length |
| **Space Complexity** | O(N) — stores each shift attempt |
| **Key Insight** | Works without brute-forcing the key space; uses language statistics |

---

#### 3.1.6 SmartPasswordPrioritizer (Greedy Heuristic)
**File:** `modules/password_cracker/smart_brute.py`

Uses the **Greedy Engine** to rank a list of candidate passwords by a heuristic scoring function before attempting them. High-scoring candidates (containing victim's name, year, common patterns) are tried first.

```
Algorithm:  Greedy Sort by heuristic score
Score:      +50 if name in password, +30 if year, +10 if "123", etc.
Rank:       sorted(candidates, key=score_func, reverse=True)
```

| Metric | Value |
|--------|-------|
| **Time Complexity** | O(W log W) — sorting W passwords |
| **Space Complexity** | O(W) — stores all scored candidates |

---

### 3.2 MITM (Man-In-The-Middle) Interception
**File:** `modules/mitm/`, external `evilginx3-master/`

Launches **Evilginx 3** (reverse proxy phishing framework) in a new terminal window. Optionally starts an ARP poisoner to redirect LAN traffic through the host.

**Algorithm:** ARP Cache Poisoning
- Broadcasts fake ARP replies: `IP(gateway) is at MAC(attacker)`
- Victim's OS updates its ARP cache → all traffic routes through attacker
- **Complexity:** O(1) per poisoning broadcast (stateless UDP-like packet send)

---

### 3.3 Zphisher (Automated Phishing)
**File:** `modules/zphisher/`

Automated phishing page generator. Launched via Bash/Git-Bash into a new terminal window. No custom algorithm — relies on pre-built phishing templates.

---

## 4. Category 2 — StiganoMessenger

### 4.1 Text-in-Text Steganography (Zero-Width XOR)
**File:** `modules/stegano/text_stegano.py`

**Encode:**
1. XOR each character of `secret_text` with repeating `key` → encrypted bytes
2. Convert each encrypted char to 8-bit binary
3. Map `0` → `U+200B` (Zero Width Space), `1` → `U+200C` (Zero Width Non-Joiner)
4. Inject these invisible Unicode chars into the `cover_text`

**Decode:** Reverse — extract zero-width chars → binary → XOR with key → plaintext

```
Algorithm:  XOR cipher + Unicode zero-width bit encoding
XOR:        char ^ key[i % len(key)]  for each char
Encoding:   8 invisible chars per secret character
```

| Metric | Value |
|--------|-------|
| **Encode Time** | O(S × 8) = O(S) — S = secret text length |
| **Decode Time** | O(T) — T = total stego-text length (scan for ZW chars) |
| **Space** | O(S × 8) invisible chars injected into cover text |
| **Security** | XOR with key provides basic symmetric encryption |

---

### 4.2 Text-in-Image Steganography (1-Bit LSB)
**File:** `modules/stegano/image_stegano.py` → `encode_text` / `decode_text`

**Encode:**
1. Convert secret text to binary string (8 bits/char) + `==EOF==` sentinel
2. For each pixel (R, G, B), replace the **Least Significant Bit** of each channel with the next secret bit: `pixel[i] = (pixel[i] & ~1) | bit`
3. Capacity: 3 bits per pixel → `W × H × 3 / 8` characters max

**Decode:** Extract LSB from every channel in scan order → reconstruct binary → chars → stop at `==EOF==`

```
Algorithm:  LSB (Least Significant Bit) substitution
Bit op:     pixel & ~1 | bit  (clears LSB, sets to secret bit)
```

| Metric | Value |
|--------|-------|
| **Encode Time** | O(W × H) — iterates all pixels |
| **Decode Time** | O(W × H) — scans until EOF |
| **Space** | O(1) extra (in-place pixel mutation) |
| **Capacity** | ⌊W × H × 3 / 8⌋ characters |
| **Perceptibility** | Invisible — 1-bit change = max 1/255 colour shift |

---

### 4.3 Image-in-Image Steganography (4-Bit LSB/MSB)
**File:** `modules/stegano/image_stegano.py` → `encode_image` / `decode_image`

**Encode:** For each pixel:
```python
new_pixel[ch] = (cover[ch] & 0xF0) | (secret[ch] >> 4)
# Keep top 4 bits of cover, inject top 4 bits of secret into lower 4
```

**Decode:**
```python
extracted[ch] = (stego[ch] & 0x0F) << 4
# Extract lower 4 bits, shift back to upper 4 → approximate colour
```

```
Algorithm:  4-bit bitwise MSB/LSB channel substitution
Operations: Bitwise AND (&), OR (|), shift (>>4, <<4)
```

| Metric | Value |
|--------|-------|
| **Encode Time** | O(W × H) — one pass over all pixels |
| **Decode Time** | O(W × H) — one pass |
| **Space** | O(W × H) — output image same size as cover |
| **Fidelity loss** | Cover loses bottom 4 bits → slight colour quantisation |
| **Secret fidelity** | Recovers top 4 bits of each channel → ~16-step colour depth |

---

## 5. Category 3 — Digital Forensics

### 5.1 Full File Analysis
**File:** `modules/forensics/investigation_tool.py` → `analyze_file`

Performs three analyses on a binary file:

#### a) Cryptographic Hashing (MD5 + SHA-256)
```
Algorithm:  Merkle–Damgård hash construction
MD5:        128-bit digest
SHA-256:    256-bit digest (collision-resistant)
```
| Metric | Value |
|--------|-------|
| **Time** | O(N) — N = file size in bytes |
| **Space** | O(1) — streaming hash, fixed internal state |

#### b) Magic Number / File Signature Detection
Compares the first bytes of the file against a lookup table of known magic numbers (e.g., `\xFF\xD8\xFF` = JPEG).
```
Algorithm:  Prefix matching against fixed dictionary
```
| **Time** | O(K) — K = number of known signatures (constant ≤ 10) |
| **Space** | O(1) |

#### c) Shannon Entropy
Measures randomness/compressibility of the file.
```
H = -Σ p(x) × log₂(p(x))   for each unique byte value x
```
- H > 7.5 → likely encrypted or packed
- H < 6.0 → plaintext / uncompressed
- 6.0–7.5 → compressed media

| Metric | Value |
|--------|-------|
| **Time** | O(N) — one pass to count byte frequencies |
| **Space** | O(256) = O(1) — counter for each possible byte value |

---

### 5.2 String Extraction
**File:** `modules/forensics/investigation_tool.py` → `extract_strings`

Scans binary file byte-by-byte. Accumulates printable ASCII characters; emits any run ≥ `min_len` (default 4) as a recovered string. Equivalent to the Unix `strings` utility.

```
Algorithm:  Linear scan with sliding accumulator
```
| Metric | Value |
|--------|-------|
| **Time** | O(N) — single pass |
| **Space** | O(N) worst case (file is all printable) |

---

### 5.3 Recursive Directory & File Scanner
**File:** `engine.py` → `DirectoryScanner`

Walks a directory tree recursively, reporting every file with its size, extension, and modification date.

```
Algorithm:  Recursive DFS tree traversal (os.walk)
```
| Metric | Value |
|--------|-------|
| **Time** | O(F + D) — F = files, D = directories |
| **Space** | O(D) — recursion depth = directory depth |

---

## 6. Category 4 — OSINT and Information Gathering

### 6.1 SQL Injector (SQLMap)
**File:** External tool `modules/sqlmap-master/sqlmap.py`, launched via `runner.py`

SQLMap is an industry-standard automated SQL injection tool. CipherPick launches it as a background subprocess with `--batch --threads=5`.

**How SQLMap works (internally):**
1. **Detection phase** — tries Boolean-based, Error-based, Time-based blind, Union-based payloads
2. **Exploitation phase** — dumps database schema and data using confirmed injection point

**Algorithm (Boolean-based blind):**
```
Binary search over ASCII values of each character:
  if response(char > 77) == TRUE → search upper half
  else → search lower half
Per character: O(log 128) = O(7) requests
```

| Metric | Value |
|--------|-------|
| **Detection Time** | O(P × T) — P = payload count, T = response time |
| **Blind extraction** | O(C × log(128)) per character — C = chars extracted |
| **Space** | O(C) — stores extracted data |

---

### 6.2 Port Scanner (Two-Phase)
**File:** `modules/scanner/port_scanner.py`

#### Phase 1 — OptimizedPortScanner (Socket Scanner)
Uses Python `socket` with **multithreading** (`ThreadPoolExecutor`) and the **GreedyEngine** to scan ports in priority order (common/high-value ports first).

```
Algorithm:  Greedy Priority Scheduling + Concurrent Socket Probing
Priority:   common_ports dict assigns scores (80→100, 443→100, etc.)
Sort:       greedy.sort_candidates(port_list)  → O(P log P)
Scan:       ThreadPoolExecutor(max_workers=N) → parallel TCP connect
```

Each port check (`connect_ex`):
- Returns 0 → open
- Returns 10061 (WSAECONNREFUSED) → closed
- Other / timeout → filtered

| Metric | Value |
|--------|-------|
| **Sort Time** | O(P log P) — P = ports to scan |
| **Scan Time** | O(P × T / W) — T = timeout, W = workers (parallelism factor) |
| **Space** | O(P) — stores results |
| **Greedy benefit** | Common ports (80, 443, 22…) found first regardless of numeric order |

#### Phase 2 — Nmap Aggressive Scan
Calls `nmap -A -vv <target>` as a subprocess and streams output through `_colorize_stream_line()` (regex-based ANSI colorizer).

```
Algorithm:  External Nmap (SYN scan + OS detection + service version + NSE scripts)
Streaming:  Line-by-line stdout pipe → regex colorizer → log file → GUI tail
```

| Metric | Value |
|--------|-------|
| **Time** | Depends on target; O(P × RTT) for all probed ports |
| **Space** | O(L) — L = lines of Nmap output buffered |

---

### 6.3 Username Hunter
**File:** `modules/osint/username_hunter.py`

Checks 22 social media platforms concurrently using `ThreadPoolExecutor(max_workers=10)`. Two detection strategies per site:

- **`status_code`** — HTTP 2xx = profile found; 404 = not found
- **`message`** — checks for known "not found" strings in the HTML response body

```
Algorithm:  Parallel HTTP probing with dual-mode existence detection
Concurrency: ThreadPoolExecutor(max_workers=10)
Detection:   HTTP status OR substring search in response HTML
```

| Metric | Value |
|--------|-------|
| **Time (serial)** | O(S × T) — S = 22 sites, T = avg HTTP timeout (10s) |
| **Time (parallel)** | O(T × ⌈S/W⌉) ≈ O(T × 3) with W=10 workers |
| **Space** | O(S) — stores result per site |
| **Speed gain** | ~7–10× faster than serial due to I/O-bound concurrency |

---

## 7. Category 5 — Cryptographic Engine

**File:** `engine.py`  
All operations use the `cryptography` Python library and are cached with `@st.cache_data`.

### 7.1 SHA-256 Hashing

One-way cryptographic hash. Implements the Merkle–Damgård construction with Davies–Meyer compression.

```python
hashlib.sha256(data).hexdigest()
```

| Metric | Value |
|--------|-------|
| **Time** | O(N) — N = input bytes |
| **Output** | 256-bit (64 hex chars) |
| **Collision resistance** | 2^128 operations (birthday bound) |
| **Space** | O(1) — fixed 256-bit internal state |

---

### 7.2 AES-128 (via Fernet)

Symmetric authenticated encryption. Fernet uses AES-128-CBC with PKCS7 padding + HMAC-SHA256 for integrity.

```
Encryption: AES-CBC(plaintext, key, IV) + HMAC-SHA256(ciphertext)
Key:        128-bit random key (URL-safe base64 encoded)
IV:         Random 128-bit per encryption (prevents ECB patterns)
```

| Metric | Value |
|--------|-------|
| **Encrypt Time** | O(N) — N = plaintext size (block-aligned) |
| **Decrypt Time** | O(N) — verify HMAC then decrypt |
| **Space** | O(N) — ciphertext same size as plaintext + overhead |
| **Block size** | 128 bits |
| **Security** | 128-bit key space = 2^128 brute-force complexity |

---

### 7.3 RSA-2048

Asymmetric encryption using the RSA trapdoor function. Uses OAEP padding with SHA-256 mask generation.

```
Key Generation: p, q = random 1024-bit primes; n = p×q; e = 65537
Encryption:     c = m^e mod n   (with OAEP padding)
Decryption:     m = c^d mod n   (d = modular inverse of e mod λ(n))
```

| Metric | Value |
|--------|-------|
| **Key generation** | O(k²) approximately — k = key size in bits; primality tests dominate |
| **Encrypt Time** | O(k²) — modular exponentiation |
| **Decrypt Time** | O(k³) — private key operation is slower |
| **Max plaintext** | 214 bytes for 2048-bit key with OAEP-SHA256 |
| **Security** | Breaking RSA-2048 requires factoring a 617-digit number |

---

## 8. Core Algorithm Engines

### 8.1 GreedyEngine
**File:** `core/greedy_engine.py`

A reusable greedy algorithm framework used by the `OptimizedPortScanner` and `SmartPasswordPrioritizer`.

```python
select_best(candidates)    # O(N) — finds max by scoring function
sort_candidates(candidates) # O(N log N) — sorts by score descending
path_search(start, expand, goal, max_steps)  # O(max_steps) greedy walk
```

**Greedy principle:** At each step, pick the locally optimal candidate without backtracking. Fast but not always globally optimal.

| Method | Time | Space |
|--------|------|-------|
| `select_best` | O(N) | O(1) |
| `sort_candidates` | O(N log N) | O(N) |
| `path_search` | O(S × B) — S=steps, B=branches | O(S) path |

---

### 8.2 RecursionEngine
**File:** `core/recursion_engine.py`

A reusable recursive traversal framework used by attack modules needing state-space exploration.

```python
dfs(state, expand, goal)          # DFS with visited set
backtrack_all(state, expand, goal) # Finds ALL solutions
traverse(state, expand)            # Full graph traversal
```

| Method | Time | Space |
|--------|------|-------|
| `dfs` | O(V + E) — V=states, E=transitions | O(V) visited set |
| `backtrack_all` | O(B^D) — B=branching, D=depth | O(D) stack depth |
| `traverse` | O(V + E) | O(V) visited set |

---

## 9. Algorithm Complexity Summary Table

| Tool | Algorithm | Time Complexity | Space Complexity |
|------|-----------|-----------------|------------------|
| Numeric Attack | Brute Force | O(10^n) | O(1) |
| Mask Attack | Recursive Backtracking | O(C^p) | O(p) |
| Trie Dictionary Attack | Trie + DFS | O(W×L) build, O(W×L) traverse | O(W×L) |
| Hash Cracker | Pre-computation + Hash Map | O(W) build, O(1) lookup | O(W) |
| Frequency Analyzer | Chi-Squared (25 shifts) | O(N) | O(N) |
| Smart Prioritizer | Greedy Sort | O(W log W) | O(W) |
| Text Steganography | XOR + Zero-Width Encode | O(S) | O(S) |
| LSB Text-in-Image | Bit Substitution | O(W×H) | O(1) |
| 4-Bit Image-in-Image | Bitwise MSB/LSB Shift | O(W×H) | O(W×H) |
| File Hash Analysis | Merkle–Damgård (SHA/MD5) | O(N) | O(1) |
| Shannon Entropy | Frequency Counter | O(N) | O(256)=O(1) |
| String Extraction | Linear Scan | O(N) | O(N) |
| Directory Scanner | DFS Tree Walk | O(F+D) | O(D) |
| Username Hunter | Parallel HTTP Probing | O(T×⌈S/W⌉) | O(S) |
| Port Scanner Ph.1 | Greedy + Concurrent Sockets | O(P log P + P×T/W) | O(P) |
| Port Scanner Ph.2 | Nmap (SYN + NSE) | O(P×RTT) | O(L) |
| SQL Injector | Boolean Binary Search | O(C×log128) per char | O(C) |
| AES-128 Encrypt | AES-CBC + HMAC | O(N) | O(N) |
| RSA-2048 Encrypt | Modular Exponentiation | O(k²) | O(k) |
| RSA-2048 Decrypt | Modular Exponentiation | O(k³) | O(k) |
| SHA-256 Hash | Merkle–Damgård | O(N) | O(1) |

**Legend:**
- N = input size (bytes or characters)
- W = wordlist size (number of words)
- L = average word length
- P = number of ports
- T = network timeout per connection
- W = thread workers
- S = number of sites (22)
- k = RSA key size in bits (2048)
- C = number of characters extracted (SQL blind)
