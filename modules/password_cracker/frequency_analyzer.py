class FrequencyAnalyzer:
    ENGLISH_FREQ = {'A': 0.082, 'B': 0.015, 'C': 0.028, 'D': 0.043, 'E': 0.130, 'F': 0.022, 'G': 0.020, 'H': 0.061,
                    'I': 0.070, 'J': 0.0015, 'K': 0.0077, 'L': 0.040, 'M': 0.024, 'N': 0.067, 'O': 0.075, 'P': 0.019,
                    'Q': 0.00095, 'R': 0.060, 'S': 0.063, 'T': 0.091, 'U': 0.028, 'V': 0.0098, 'W': 0.024, 'X': 0.0015,
                    'Y': 0.020, 'Z': 0.00074}

    @staticmethod
    def decrypt_caesar(ciphertext):
        print("\n[*] Initializing Chi-Squared statistical analysis...")
        best_shift, lowest_chi_sq, best_plaintext = 0, float('inf'), ""
        for shift in range(1, 26):
            attempt = ""
            for char in ciphertext:
                if char.isalpha():
                    ascii_offset = 65 if char.isupper() else 97
                    attempt += chr((ord(char) - ascii_offset - shift) % 26 + ascii_offset)
                else:
                    attempt += char

            chi_sq, total_letters = 0, sum(1 for c in attempt if c.isalpha())
            if total_letters == 0: continue

            for letter in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
                observed = attempt.upper().count(letter)
                expected = total_letters * FrequencyAnalyzer.ENGLISH_FREQ[letter]
                if expected > 0: chi_sq += ((observed - expected) ** 2) / expected

            if chi_sq < lowest_chi_sq:
                lowest_chi_sq, best_shift, best_plaintext = chi_sq, shift, attempt

        print(f"\n[+] Statistical match found (Shift: {best_shift}, Variance: {lowest_chi_sq:.2f})")
        print(f"[+] Decrypted Text:\n{best_plaintext}")
