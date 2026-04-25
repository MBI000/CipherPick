import os
import hashlib

class HashCracker:
    @staticmethod
    def crack(target_hash, wordlist_path, algorithm='md5'):
        print(f"\n[*] Generating O(1) Hashmap for '{wordlist_path}' using {algorithm.upper()}...")
        hash_map = {}
        if not os.path.exists(wordlist_path):
            print(f"[!] ERROR: Wordlist not found.")
            return
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                word = line.strip()
                computed = hashlib.md5(word.encode()).hexdigest() if algorithm == 'md5' else hashlib.sha256(
                    word.encode()).hexdigest()
                hash_map[computed] = word
        print(f"[*] Hashmap built. Initiating O(1) lookup...")
        if target_hash in hash_map:
            print(f"\n[+] SUCCESS: Hash cracked! Plaintext -> {hash_map[target_hash]}")
        else:
            print("\n[-] FAILURE: Hash not found in the generated map.")
