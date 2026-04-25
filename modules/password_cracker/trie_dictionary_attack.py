import os
from core.attack_base import AttackStrategy, attempt_pdf_unlock

class TrieNode:
    def __init__(self):
        self.children = {}
        self.is_end = False

class TrieDictionaryAttack(AttackStrategy):
    def __init__(self, pdf_file_path, wordlist_path):
        super().__init__(pdf_file_path)
        self.wordlist_path = wordlist_path
        self.root = TrieNode()

    def _insert(self, word):
        node = self.root
        for char in word:
            if char not in node.children: node.children[char] = TrieNode()
            node = node.children[char]
        node.is_end = True

    def _dfs_traverse(self, node, current_prefix):
        if node.is_end:
            yield current_prefix
            yield current_prefix + "123"
            yield current_prefix + "!"
        for char, child_node in node.children.items():
            yield from self._dfs_traverse(child_node, current_prefix + char)

    def execute(self):
        print(f"\n[*] Building Trie from wordlist: {self.wordlist_path}...")
        if not os.path.exists(self.wordlist_path):
            print(f"[!] ERROR: Could not open {self.wordlist_path}")
            return
        with open(self.wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f: self._insert(line.strip())

        print("[*] Trie built. Starting DFS traversal and mutation attack...")
        for guess in self._dfs_traverse(self.root, ""):
            if attempt_pdf_unlock(self.pdf_file_path, guess):
                print(f"\n[+] SUCCESS: Password found -> {guess}")
                return
        print("\n[-] FAILURE: Password not found in dictionary Trie.")
