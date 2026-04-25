from core.attack_base import AttackStrategy, attempt_pdf_unlock

class MaskAttack(AttackStrategy):
    def __init__(self, pdf_file_path, mask):
        super().__init__(pdf_file_path)
        self.mask = mask
        self.charset_map = {'?d': '0123456789', '?l': 'abcdefghijklmnopqrstuvwxyz'}
        self.found = False

    def _backtrack(self, current_guess, index):
        if self.found: return
        if index == len(self.mask):
            if attempt_pdf_unlock(self.pdf_file_path, current_guess):
                print(f"\n[+] SUCCESS: Password found -> {current_guess}")
                self.found = True
            return

        if index + 1 < len(self.mask) and self.mask[index] == '?':
            token = self.mask[index:index + 2]
            if token in self.charset_map:
                for char in self.charset_map[token]:
                    self._backtrack(current_guess + char, index + 2)
            else:
                self._backtrack(current_guess + self.mask[index], index + 1)
        elif self.mask[index] != '?':
            self._backtrack(current_guess + self.mask[index], index + 1)

    def execute(self):
        print(f"\n[*] Starting mask attack with pattern: {self.mask}...")
        self._backtrack("", 0)
        if not self.found: print("\n[-] FAILURE: Password not found using mask.")
