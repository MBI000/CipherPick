class TextSteganography:
    ZW_0, ZW_1 = '\u200B', '\u200C'

    @staticmethod
    def encode():
        cover_text = input("\nEnter normal-looking cover text:\n> ")
        secret_text = input("Enter secret message to hide:\n> ")
        key = input("Enter XOR encryption key:\n> ")
        hidden_bits = ""
        for i, char in enumerate(secret_text):
            encrypted_char = chr(ord(char) ^ ord(key[i % len(key)]))
            for bit in format(ord(encrypted_char), '08b'):
                hidden_bits += TextSteganography.ZW_1 if bit == '1' else TextSteganography.ZW_0
        result = hidden_bits if not cover_text else cover_text[0] + hidden_bits + cover_text[1:]
        print("\n[+] Stego-Text Generated! Copy the entire line below:\n" + "-" * 50 + f"\n{result}\n" + "-" * 50)

    @staticmethod
    def decode():
        stego_text = input("\nPaste the text containing the hidden message:\n> ")
        key = input("Enter XOR decryption key:\n> ")
        secret, current_bits = "", ""
        for char in stego_text:
            if char == TextSteganography.ZW_0:
                current_bits += '0'
            elif char == TextSteganography.ZW_1:
                current_bits += '1'
            if len(current_bits) == 8:
                secret += chr(ord(chr(int(current_bits, 2))) ^ ord(key[len(secret) % len(key)]))
                current_bits = ""
        if secret:
            print("\n[+] Secret Message Decoded:\n" + "-" * 50 + f"\n{secret}\n" + "-" * 50)
        else:
            print("\n[-] No hidden message found or invalid text.")
