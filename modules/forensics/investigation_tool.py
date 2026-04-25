import os
import hashlib
import math
from collections import Counter
import string

class InvestigationTool:
    MAGIC_NUMBERS = {
        b'\xFF\xD8\xFF': "JPEG Image",
        b'\x89PNG\r\n\x1a\n': "PNG Image",
        b'%PDF-': "PDF Document",
        b'PK\x03\x04': "ZIP Archive",
        b'MZ': "Windows Executable (EXE/DLL)",
        b'\x7FELF': "Linux Executable (ELF)"
    }

    @staticmethod
    def analyze_file(filepath):
        if not os.path.exists(filepath):
            print(f"[!] ERROR: File '{filepath}' not found.")
            return

        print(f"\n[*] Initiating Digital Forensics Analysis on '{os.path.basename(filepath)}'...\n" + "=" * 50)

        with open(filepath, 'rb') as f:
            data = f.read()

        # 1. Hashes & Size
        size = len(data)
        md5_hash = hashlib.md5(data).hexdigest()
        sha256_hash = hashlib.sha256(data).hexdigest()

        print(f"File Size : {size} bytes")
        print(f"MD5 Hash  : {md5_hash}")
        print(f"SHA256    : {sha256_hash}")

        # 2. Magic Number Detection
        file_signature = "Unknown/Plaintext"
        for magic, name in InvestigationTool.MAGIC_NUMBERS.items():
            if data.startswith(magic):
                file_signature = name
                break
        print(f"Signature : {file_signature}")

        # 3. Shannon Entropy
        freq = Counter(data)
        entropy = 0.0
        for count in freq.values():
            p = count / size
            entropy -= p * math.log2(p)

        print(f"Entropy   : {entropy:.4f}")

        if entropy > 7.5:
            print("   -> [!] WARNING: High entropy detected! File is likely packed, encrypted, or hiding data.")
        elif entropy < 6.0:
            print("   -> [*] Low entropy. File is likely uncompressed plaintext or native data.")
        else:
            print("   -> [*] Moderate entropy. Typical for compressed files or complex media.")
        print("=" * 50)

    @staticmethod
    def extract_strings(filepath, min_len=4):
        if not os.path.exists(filepath):
            print(f"[!] ERROR: File '{filepath}' not found.")
            return

        print(f"\n[*] Extracting ASCII strings (min length {min_len}) from '{os.path.basename(filepath)}'...")
        with open(filepath, 'rb') as f:
            data = f.read()

        result = []
        current_string = ""
        printable = set(string.printable.encode())

        for byte in data:
            if byte in printable and byte not in b'\n\r\t':
                current_string += chr(byte)
            else:
                if len(current_string) >= min_len:
                    result.append(current_string)
                current_string = ""

        # Append remaining string if loop ends
        if len(current_string) >= min_len:
            result.append(current_string)

        print("-" * 50)
        for s in result[:20]:  # Print first 20 strings
            print(s)
        if len(result) > 20:
            print(f"... and {len(result) - 20} more strings.")
        print("-" * 50)
