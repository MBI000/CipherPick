import os

try:
    from PIL import Image
except ImportError:
    Image = None

class ImageSteganography:
    @staticmethod
    def encode_text(image_path=None, secret_text=None, output_path=None):
        if Image is None:
            print("[!] Warning: 'Pillow' library not found. Image Steganography will not work.")
            return
        if image_path is None:
            image_path = input("\nEnter path to cover image (e.g., cover.png):\n> ")
        if secret_text is None:
            secret_text = input("Enter secret message to hide:\n> ")
        if output_path is None:
            output_path = input("Enter output image name (e.g., hidden.png):\n> ")
        
        secret_text += "==EOF=="

        img = Image.open(image_path).convert('RGB')
        encoded, pixels = img.copy(), img.copy().load()
        binary_secret = ''.join(format(ord(char), '08b') for char in secret_text)
        data_index, binary_length = 0, len(binary_secret)

        for y in range(img.size[1]):
            for x in range(img.size[0]):
                if data_index >= binary_length: break
                pixel = list(pixels[x, y])
                for i in range(3):
                    if data_index < binary_length:
                        pixel[i] = pixel[i] & ~1 | int(binary_secret[data_index])
                        data_index += 1
                pixels[x, y] = tuple(pixel)
        encoded.save(output_path)
        print(f"\n[+] Success! Text hidden. Saved as '{output_path}'.")

    @staticmethod
    def decode_text(image_path=None):
        if Image is None:
            print("[!] Warning: 'Pillow' library not found. Image Steganography will not work.")
            return
        if image_path is None:
            image_path = input("\nEnter path to stego-image:\n> ")
        img = Image.open(image_path).convert('RGB')
        pixels, binary_data = img.load(), ""

        for y in range(img.size[1]):
            for x in range(img.size[0]):
                for i in range(3): binary_data += str(pixels[x, y][i] & 1)

        secret = ""
        for i in range(0, len(binary_data), 8):
            byte = binary_data[i:i + 8]
            if len(byte) == 8:
                secret += chr(int(byte, 2))
                if secret.endswith("==EOF=="):
                    print("\n[+] Secret Text Decoded:\n" + "-" * 50 + f"\n{secret[:-7]}\n" + "-" * 50)
                    return
        print("\n[-] No hidden text found.")

    @staticmethod
    def encode_image(cover_path=None, secret_path=None, output_path=None):
        if Image is None: return
        
        print("\n--- Encode: Hide Image inside Image ---")
        if not cover_path:
            cover_path = input("Enter path to COVER image (e.g., cover.png):\n> ")
        if not secret_path:
            secret_path = input("Enter path to SECRET image to hide (e.g., secret.png):\n> ")
        if not output_path:
            output_path = input("Enter output name for the new stego-image (e.g., stego.png):\n> ")

        if not os.path.exists(cover_path) or not os.path.exists(secret_path):
            print("[!] ERROR: One or both image paths do not exist.")
            return

        # Load images and convert to RGB
        cover_img = Image.open(cover_path).convert('RGB')
        secret_img = Image.open(secret_path).convert('RGB')

        # Resize secret image to perfectly match the cover image's matrix dimensions
        if secret_img.size != cover_img.size:
            print("[*] Resizing secret image to match cover dimensions...")
            secret_img = secret_img.resize(cover_img.size)

        encoded_img = cover_img.copy()
        cover_pixels = encoded_img.load()
        secret_pixels = secret_img.load()

        # Matrix Manipulation: 4-Bit LSB/MSB Shift
        for y in range(cover_img.size[1]):
            for x in range(cover_img.size[0]):
                c_p = cover_pixels[x, y]
                s_p = secret_pixels[x, y]
                
                # Keep top 4 bits of cover (c_p & 0xF0)
                # Take top 4 bits of secret and shift them down (s_p >> 4)
                # Combine them using Bitwise OR (|)
                new_pixel = (
                    (c_p[0] & 0xF0) | (s_p[0] >> 4),
                    (c_p[1] & 0xF0) | (s_p[1] >> 4),
                    (c_p[2] & 0xF0) | (s_p[2] >> 4)
                )
                cover_pixels[x, y] = new_pixel

        encoded_img.save(output_path)
        print(f"\n[+] SUCCESS! Secret image is now hidden inside '{output_path}'.")

    @staticmethod
    def decode_image(stego_path=None, output_path=None):
        if Image is None: return
        
        print("\n--- Decode: Extract Hidden Image ---")
        if not stego_path:
            stego_path = input("Enter path to STEGO-IMAGE (e.g., stego.png):\n> ")
        if not output_path:
            output_path = input("Enter output name for the extracted secret (e.g., extracted.png):\n> ")

        if not os.path.exists(stego_path):
            print("[!] ERROR: Stego-image not found.")
            return

        stego_img = Image.open(stego_path).convert('RGB')
        extracted_img = Image.new('RGB', stego_img.size)
        
        stego_pixels = stego_img.load()
        extracted_pixels = extracted_img.load()

        # Matrix Manipulation: Reverse the shift
        for y in range(stego_img.size[1]):
            for x in range(stego_img.size[0]):
                p = stego_pixels[x, y]
                
                # Extract the bottom 4 bits (p & 0x0F)
                # Shift them back up to the top 4 bits (<< 4) to restore color vectors
                extracted_pixels[x, y] = (
                    (p[0] & 0x0F) << 4,
                    (p[1] & 0x0F) << 4,
                    (p[2] & 0x0F) << 4
                )

        extracted_img.save(output_path)
        print(f"\n[+] SUCCESS! Hidden image extracted and saved as '{output_path}'.")
