from core.attack_base import AttackStrategy, attempt_pdf_unlock

class NumericAttack(AttackStrategy):
    def __init__(self, pdf_file_path, length):
        super().__init__(pdf_file_path)
        self.length = length

    def execute(self):
        print(f"\n[*] Starting numeric brute-force for length: {self.length}...")
        max_combinations = 10 ** self.length
        for i in range(max_combinations):
            current_guess = f"{i:0{self.length}d}"
            if attempt_pdf_unlock(self.pdf_file_path, current_guess):
                print(f"\n[+] SUCCESS: Password found -> {current_guess}")
                return
        print("\n[-] FAILURE: Password not found in numeric space.")
