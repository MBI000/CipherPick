import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from core.recursion_engine import RecursionEngine

class AdvancedPasswordGenerator:
    def __init__(self, base_words, max_len=3):
        self.base_words = base_words
        self.engine = RecursionEngine(limit=max_len)
        self.leetspeak_map = {'a': '@', 'e': '3', 'i': '1', 'o': '0', 's': '$'}

    def apply_leetspeak(self, word):
        return ''.join(self.leetspeak_map.get(c.lower(), c) for c in word)

    def expand(self, state):
        expansions = []
        for word in self.base_words:
            expansions.append(state + word)
            expansions.append(state + word.capitalize())
            expansions.append(state + self.apply_leetspeak(word))
        # Add common suffixes
        expansions.append(state + "123")
        expansions.append(state + "!")
        return expansions

    def generate(self, start=""):
        print(f"\n[*] Recursively generating password combinations from bases: {self.base_words}")
        
        results = set(self.engine.traverse(start, self.expand, depth=0))
        if "" in results: results.remove("")
        
        print(f"[+] Generated {len(results)} combinations.")
        return list(results)
