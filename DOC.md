# CipherPick Framework: Comprehensive Algorithmic and Mathematical Theory

**Author:** Mahmoud Basem Ibrahim Ismail (ID: 2401153)  
**Institution:** AlRyada University for Science and Technology  
**Course:** algorithm
**Professor:** Prof\Mohamed Badawy  
**Teaching Assistant:** Eng\Ahmed Ali

---

## Abstract
This document provides a highly detailed theoretical breakdown of the algorithms, data structures, and mathematical models utilized within the CipherPick framework. It expands upon foundational theories by defining the specific description, algorithmic execution, and precise Big-O Time and Space complexities for every tool integrated into the system, including the advanced Greedy and Recursive modules.

---

## 1. Password Cracking Vectors

### 1.1 PDF Numeric Brute-Force
**Description:**  
An offensive tool designed to unlock PDF files by exhaustively guessing pure numeric combinations of an exact, predefined length.

**Algorithm (Sequential Iteration with Zero-Padding):**  
The algorithm converts integers into zero-padded strings to ensure cryptographic formatting requirements are met, iterating sequentially from zero to the mathematical maximum.

**Time Complexity:**  
$\mathcal{O}(10^L)$ where $L$ is the target length; as $L$ increases, computational time grows exponentially.

**Space Complexity:**  
$\mathcal{O}(L)$ to store the generated string; practically $\mathcal{O}(1)$ as previous guesses are discarded.

---

### 1.2 PDF Mask Attack
**Description:**  
A targeted brute-force tool that reduces the search space by using a mask (e.g., `admin?d?d`) to constrain the combinatorial explosion.

**Algorithm (Recursive Backtracking):**  
Utilizes a Depth-First Search (DFS) across the combinatorial tree. It prunes branches that fail cryptographic checks and backtracks to the previous valid node.

**Time Complexity:**  
$\mathcal{O}(\prod_{i=1}^{n} |S_i|)$ where $n$ is the number of variables and $|S_i|$ is the character set size for position $i$.

**Space Complexity:**  
$\mathcal{O}(M)$ where $M$ is the length of the mask, dictated by the maximum depth of the recursive call stack.

---

### 1.3 PDF Dictionary Attack (Trie/DFS Mutation)
**Description:**  
A memory-efficient dictionary attacker that tests words from a file and dynamically applies suffix mutations (like `"123"` or `"!"`) in real-time.

**Algorithm (Prefix Tree & DFS Traversal):**  
The wordlist is parsed into a Prefix Tree (Trie) where shared prefixes occupy the same root memory nodes. DFS traverses the graph to yield base words and apply mutations at leaf nodes.

**Time Complexity:**  
- **Build Phase:** $\mathcal{O}(W \cdot K)$ where $W$ is the number of words and $K$ is the maximum word length.  
- **Execution Phase:** $\mathcal{O}(V \cdot m)$ where $V$ is the number of unique Trie nodes and $m$ is the number of dynamic mutations.

**Space Complexity:**  
$\mathcal{O}(W \cdot K)$ in the worst-case, but practically $\mathcal{O}(V)$, which reduces RAM utilization.

---

### 1.4 Advanced Password Generator (Recursive Generation)
**Description:**  
Generates a vast dictionary of combinations from a set of base words by recursively appending leetspeak variations, capitalizations, and common symbols/suffixes.

**Algorithm (Depth-Limited Recursion):**  
Explores all branches of a combination tree up to a predefined depth (length limit). At each depth layer, it branches by appending mutations to the current string state.

**Time Complexity:**  
$\mathcal{O}(M^D)$, where $M$ is the number of mutation branches per node and $D$ is the maximum recursive depth limit.

**Space Complexity:**  
$\mathcal{O}(D)$ for the recursive call stack depth, plus $\mathcal{O}(M^D)$ to maintain the generated unique combinations in memory.

---

### 1.5 Smart Password Prioritization (Greedy Heuristics)
**Description:**  
Optimizes dictionary and brute-force attacks by scoring a list of passwords against a user context profile (e.g., name, year, common structures) and executing the most likely candidates first.

**Algorithm (Greedy Sorting):**  
Applies a heuristic scoring function to every candidate independently, generating a mathematical weight. It sorts them descendingly, ensuring the most promising guesses are attempted first.

**Time Complexity:**  
$\mathcal{O}(P \log P)$, where $P$ is the total number of passwords, bounded heavily by the sorting algorithm's efficiency.

**Space Complexity:**  
$\mathcal{O}(P)$ to maintain the ranked lists in memory.

---

## 2. Cryptanalysis & Hash Reversal

### 2.1 Hashmap Time-Memory Trade-Off (Hash Cracker)
**Description:**  
A cryptanalytic tool that reverses deterministic one-way cryptographic functions by sacrificing auxiliary storage space to bypass computational constraints.

**Algorithm (Hashmap/Dictionary Pre-computation):**  
Sequentially hashes a wordlist and constructs a Hashmap using hashes as keys and plaintexts as values.

**Time Complexity:**  
- **Pre-computation:** $\mathcal{O}(N \cdot H)$  
- **Lookup Attack:** $\mathcal{O}(1)$ average

**Space Complexity:**  
$\mathcal{O}(N \cdot S)$ where $S$ is the size of stored data.

---

### 2.2 Frequency Analyzer
**Description:**  
An automated statistical tool that decrypts classical substitution ciphers (like Caesar) without a cryptographic key.

**Algorithm (Chi-Squared Minimization):**  
Applies modular arithmetic to attempt all possible shifts and computes the Chi-Squared ($\chi^2$) variance between observed and expected letter frequencies.

**Time Complexity:**  
$\mathcal{O}(K \cdot C)$ where $K = 26$, simplifies to $\mathcal{O}(C)$.

**Space Complexity:**  
$\mathcal{O}(C)$.

---

## 3. Advanced Steganography

### 3.1 StiganoMessenger (Text-in-Text XOR)
**Description:**  
A covert communication tool that encrypts a payload and embeds it invisibly within plaintext using zero-width characters.

**Algorithm (Bitwise XOR & Zero-Width Injection):**  
Applies XOR ($\oplus$) encryption, then converts ciphertext into an $8$-bit binary stream mapped to Unicode Zero-Width characters (`\u200B`, `\u200C`).

**Time Complexity:**  
$\mathcal{O}(P)$ where $P$ is the payload length.

**Space Complexity:**  
$\mathcal{O}(P \cdot 8)$.

---

### 3.2 Image Steganography (1-Bit LSB & 4-Bit LSB/MSB)
**Description:**  
A tool for hiding textual payloads or secondary images within pixel data.

**Algorithm (Bitwise Masking):**
- **Text (1-Bit LSB):** Clears LSB using AND, injects payload using OR.  
- **Image (4-Bit):** Extracts MSBs and overwrites lower bits of cover image.

**Time Complexity:**  
$\mathcal{O}(W \cdot H)$.

**Space Complexity:**  
$\mathcal{O}(W \cdot H)$.

---

## 4. Digital Forensics & Investigation

### 4.1 Full File Analysis (Entropy & Signatures)
**Description:**  
Determines true file identity and detects packed or encrypted malicious data.

**Algorithm (Shannon Entropy & Byte-Mapping):**  
Verifies magic numbers and computes entropy using byte frequency distribution.

**Time Complexity:**  
$\mathcal{O}(B)$.

**Space Complexity:**  
$\mathcal{O}(1)$.

---

### 4.2 Binary String Extraction
**Description:**  
Extracts human-readable strings from compiled binaries.

**Algorithm (State Machine Parsing):**  
Scans bytes and buffers printable ASCII sequences exceeding a threshold.

**Time Complexity:**  
$\mathcal{O}(B)$.

**Space Complexity:**  
$\mathcal{O}(S)$.

---

### 4.3 Text Analysis & Comparison (Regex IoC Extraction)
**Description:**  
Evaluates text differences and extracts Indicators of Compromise (IoCs).

**Algorithm (Finite State Automata via Regex):**  
Matches patterns for IPs, emails, and URLs.

**Time Complexity:**  
$\mathcal{O}(N)$.

**Space Complexity:**  
$\mathcal{O}(M)$.

---

### 4.4 Recursive Directory & File Scanner
**Description:**  
Traverses deep and complex directory structures to locate hidden files or suspicious extensions (like `.env`, `.key`).

**Algorithm (Graph DFS over Filesystem):**  
Uses recursive Depth-First Search to explore nodes (directories) and leaves (files), tracking paths to prevent infinite symbolic link loops.

**Time Complexity:**  
$\mathcal{O}(V + E)$, where $V$ is the number of directories/files and $E$ is the parent-child relationships.

**Space Complexity:**  
$\mathcal{O}(D)$, where $D$ is the maximum nested depth of the file system tree.

---

## 5. OSINT and Information Gathering (Greedy Optimization)

### 5.1 Recursive Web Crawler
**Description:**  
Automates the extraction of endpoints and URLs from a target domain, diving into sub-links up to a specified depth limit.

**Algorithm (Graph Traversal with Visited Sets):**  
Explores hyperlinks via a recursive network traversal engine. Maintains a global hash set to eliminate cycles and redundant parsing.

**Time Complexity:**  
$\mathcal{O}(V + E)$, where $V$ represents unique URLs visited and $E$ represents the links between them.

**Space Complexity:**  
$\mathcal{O}(V)$ to maintain the hash set of visited endpoints and paths in memory.

---

### 5.2 Optimized Port Scanner 
**Description:**  
Scans target IPs for open ports by prioritizing the most mathematically common and high-value ports (e.g., 80, 443, 22) rather than scanning sequentially, utilizing asynchronous network sockets.

**Algorithm (Greedy Priority + ThreadPool):**  
Employs a Greedy heuristic to rank ports based on predefined mathematical probability weights. It then utilizes concurrent multithreading to dispatch non-blocking TCP socket requests in order of priority.

**Time Complexity:**  
$\mathcal{O}(\frac{N}{T})$, where $N$ is the number of ports scanned and $T$ is the active thread count.

**Space Complexity:**  
$\mathcal{O}(N)$ to maintain the priority queue and track active/closed socket states in memory.

---

### 5.3 Username Hunter 
**Description:**  
Hunts for the presence of a specific user identity across dozens of high-value social media platforms simultaneously.

**Algorithm (Concurrent HTTP Probing & Soft-404 Detection):**  
Dispatches concurrent HTTP GET requests mapped to platform schemas. Analyzes HTTP response codes, tracks silent URL redirects, and scans HTML payloads against known error signatures (heuristics) to definitively confirm profile existence and prevent false positives.

**Time Complexity:**  
$\mathcal{O}(\frac{S}{T})$, where $S$ is the number of targeted social media sites and $T$ is the active thread pool allocation.

**Space Complexity:**  
$\mathcal{O}(T)$ to buffer and process concurrent HTTP network streams and HTML response chunks in RAM.