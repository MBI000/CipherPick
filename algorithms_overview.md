# Algorithms Overview in CipherPick

This document outlines the usage of Brute Force, Greedy, and Dynamic Programming algorithms within the CipherPick project, detailing the specific tools and functions built upon them.

## 1. Brute Force (Exhaustive Search)
**Used in project:** Yes.

Brute force algorithms systematically enumerate all possible candidates for the solution and check whether each candidate satisfies the problem's statement.

### Tools and Functions:
- **`NumericAttack` (`modules/password_cracker/numeric_attack.py`)**: 
  - Iterates through the entire numerical space for a given length (e.g., `000` to `999`) to attempt unlocking a PDF file (`attempt_pdf_unlock`). This is a classic exhaustive brute-force attack.
- **`RecursionEngine` (`core/recursion_engine.py`)**: 
  - Implements exhaustive traversal functions such as `dfs` (Depth First Search), `backtrack_all` (finding all valid solutions via backtracking), and `traverse`. It explores state spaces recursively up to a specified depth limit.

## 2. Greedy Algorithm
**Used in project:** Yes.

A greedy algorithm makes the locally optimal choice at each stage with the hope of finding a global optimum. In the context of password cracking, it is used to prioritize testing the most probable passwords first based on heuristic scoring.

### Tools and Functions:
- **`GreedyEngine` (`core/greedy_engine.py`)**: 
  - Provides core greedy methods such as `select_best`, `sort_candidates`, and `path_search`. It evaluates states or candidates using a provided `scoring_func` and selects the ones that yield the highest score.
- **`SmartPasswordPrioritizer` (`modules/password_cracker/smart_brute.py`)**: 
  - Utilizes the `GreedyEngine` to rank a list of password candidates. It defines a `score_password` heuristic function that assigns points based on whether the password contains user context info (like user's name or birth year), common patterns (e.g., "123" or "!"), and length. Passwords with the highest scores are tested first.

## 3. Dynamic Programming
**Used in project:** No (Potential Future Use).

Dynamic programming (DP) is a method for solving complex problems by breaking them down into simpler overlapping subproblems, solving each of those subproblems just once, and storing their solutions (via memoization or tabulation).

### Current Status:
- Currently, there are no core engines or modules in the CipherPick project that implement Dynamic Programming. While the `RecursionEngine` uses a `visited` set to prevent infinite loops during state traversal, it does not cache the results of subproblems to optimize overlapping computations, which is the defining characteristic of DP.

### Potential Future Implementations:
1. **Memoization in `RecursionEngine` (State Caching)**: If multiple paths lead to the same intermediate state (e.g., when crawling deeply interlinked domains in the OSINT crawler, or mapping a network graph), a memoized engine would immediately return the cached outcome for that node instead of redundantly exploring its children again.
2. **Intelligent Password Mutation (Levenshtein Edit Distance)**: In `smart_brute.py`, DP can be used to generate or score password variations. By calculating the edit distance from known user context words, it can efficiently find all common typos or "leetspeak" substitutions (e.g., `mahmoud` -> `M4hmoud`).
3. **Optimal Attack Scheduling (0/1 Knapsack Problem)**: Given limited time/resources to crack a target using various modules, a DP Knapsack algorithm can calculate the optimal combination of attack modules to execute to maximize chances of cracking based on their time cost and probability of success weight.
4. **Network Payload Signature Extraction (Longest Common Subsequence)**: For MITM interception or the OSINT crawler, LCS can efficiently extract hidden, recurring credential structures or tracking signatures across multiple raw packet payloads or messy HTML strings.
