import sys
import os
import subprocess

from modules.osint.graph_explorer import GraphExplorer
from modules.osint.target_prioritizer import TargetPrioritizer
from modules.password_cracker.generator import AdvancedPasswordGenerator
from modules.password_cracker.smart_brute import SmartPasswordPrioritizer
from modules.scanner.dir_scanner import DirectoryScanner
from modules.scanner.port_scanner import OptimizedPortScanner
from modules.osint.username_hunter import UsernameHunter

# New imports
from modules.password_cracker.numeric_attack import NumericAttack
from modules.password_cracker.mask_attack import MaskAttack
from modules.password_cracker.trie_dictionary_attack import TrieDictionaryAttack
from modules.password_cracker.hash_cracker import HashCracker
from modules.password_cracker.frequency_analyzer import FrequencyAnalyzer

from modules.stegano.text_stegano import TextSteganography
from modules.stegano.image_stegano import ImageSteganography

from modules.forensics.investigation_tool import InvestigationTool


# ==========================================
# MENUS
# ==========================================
def attacks_menu():
    while True:
        print("\n--- Attacks Menu ---")
        print("1. PDF Numeric Brute-Force")
        print("2. PDF Dictionary Attack (Trie/DFS Mutation)")
        print("3. PDF Mask Attack (Backtracking)")
        print("4. Hash Cracker (O(1) Map)")
        print("5. Cryptanalysis: Frequency Analyzer")
        print("6. Advanced Password Generator (Recursion)")
        print("7. Smart Password Prioritization (Greedy)")
        print("8. Back to Main Menu")

        choice = input("Select an attack: ")

        if choice in ['1', '2', '3']:
            pdf_path = input("\nEnter PDF path:\n> ")
            if choice == '1':
                try:
                    NumericAttack(pdf_path, int(input("Enter length: "))).execute()
                except ValueError:
                    print("\n[!] Invalid input.")
            elif choice == '2':
                TrieDictionaryAttack(pdf_path, input("Enter wordlist path:\n> ")).execute()
            elif choice == '3':
                MaskAttack(pdf_path, input("Enter mask (?d=digit, ?l=letter):\n> ")).execute()
        elif choice == '4':
            HashCracker.crack(input("Enter target hash:\n> "), input("Enter wordlist path:\n> "),
                              input("Algorithm (md5/sha256): ").lower())
        elif choice == '5':
            FrequencyAnalyzer.decrypt_caesar(input("Enter the encrypted text:\n> "))
        elif choice == '6':
            words = input("\nEnter base words separated by space:\n> ").split()
            AdvancedPasswordGenerator(words).generate()
        elif choice == '7':
            pwds = input("\nEnter passwords to rank separated by space:\n> ").split()
            name = input("Enter target name context (optional):\n> ")
            year = input("Enter target year context (optional):\n> ")
            SmartPasswordPrioritizer({"name": name, "year": year}).rank_passwords(pwds)
        elif choice == '8':
            break
        else:
            print("\n[!] Invalid selection.")


def steganography_menu():
    while True:
        print("\n--- StiganoMessenger ---")
        print("1. Encode Text in Text (Zero-Width XOR)")
        print("2. Decode Text from Text (Zero-Width XOR)")
        print("3. Encode Text in Image (1-Bit LSB)")
        print("4. Decode Text from Image (1-Bit LSB)")
        print("5. Encode Image in Image (4-Bit LSB/MSB)")
        print("6. Decode Image from Image (4-Bit LSB/MSB)")
        print("7. Back to Main Menu")

        choice = input("Select an option: ")

        if choice == '1':
            TextSteganography.encode()
        elif choice == '2':
            TextSteganography.decode()
        elif choice == '3':
            ImageSteganography.encode_text()
        elif choice == '4':
            ImageSteganography.decode_text()
        elif choice == '5':
            ImageSteganography.encode_image()
        elif choice == '6':
            ImageSteganography.decode_image()
        elif choice == '7':
            break
        else:
            print("\n[!] Invalid selection.")


def digital_forensics_menu():
    while True:
        print("\n--- Digital Forensics ---")
        print("1. Full File Analysis (Hashes, Signature, Entropy)")
        print("2. Extract Strings from Binary")
        print("3. Recursive Directory & File Scanner")
        print("4. Back to Main Menu")

        choice = input("Select an option: ")

        if choice in ['1', '2']:
            filepath = input("\nEnter path to target file:\n> ")
            if choice == '1':
                InvestigationTool.analyze_file(filepath)
            elif choice == '2':
                InvestigationTool.extract_strings(filepath)
        elif choice == '3':
            root = input("\nEnter root directory path to scan:\n> ")
            DirectoryScanner(root).scan()
        elif choice == '4':
            break
        else:
            print("\n[!] Invalid selection.")


def osint_menu():
    while True:
        print("\n--- OSINT and Information Gathering ---")
        print("1. SQL Injector")
        print("2. Port Scanner")
        print("3. Username Hunter")
        print("4. Back to Main Menu")

        choice = input("Select an option: ")

        if choice == '1':
            url = input("\nEnter target URL for SQL testing:\n> ")
            print("\n[+] Starting SQLMap...")
            subprocess.run([sys.executable, "modules/sqlmap-master/sqlmap.py", "-u", url, "--batch"])
        elif choice == '2':
            target = input("\nEnter target IP/Domain:\n> ")
            print("\nSelect ports to scan:")
            print("  - 'all' for 1->65535")
            print("  - 'common' for top 20 common ports")
            print("  - Or enter space-separated ports (e.g., 80 443 22)")
            ports_input = input("> ").strip().lower()
            
            port_list = []
            if ports_input == 'all':
                port_list = list(range(1, 65536))
            elif ports_input == 'common':
                port_list = [80, 443, 21, 22, 23, 25, 53, 110, 111, 135, 139, 143, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
            else:
                try:
                    port_list = [int(p) for p in ports_input.split()]
                except ValueError:
                    print("\n[!] Invalid port list. Please enter numbers, 'all', or 'common'.")
            
            if port_list:
                OptimizedPortScanner(target).scan(port_list)
        elif choice == '3':
            username = input("\nEnter target username to hunt:\n> ")
            UsernameHunter(username).hunt()
        elif choice == '4':
            break
        else:
            print("\n[!] Invalid selection.")


def main():
    print("   _____ _       _               _____ _      _         ")
    print("  / ____(_)     | |             |  __ (_)    | |        ")
    print(" | |     _ _ __ | |__   ___ _ __| |__) |  ___| | __     ")
    print(" | |    | | '_ \\| '_ \\ / _ \\ '__|  ___/ |/ __| |/ /     ")
    print(" | |____| | |_) | | | |  __/ |  | |   | | (__|   <      ")
    print("  \\_____|_| .__/|_| |_|\\___|_|  |_|   |_|\\___|_|\\_\\_    ")
    print(" |  ____| | |                                     | |   ")
    print(" | |__ _ _|_|_ _ _ __ ___   _____      _____  _ __| | __")
    print(" |  __| '__/ _` | '_ ` _ \\ / _ \\ \\ /\\ / / _ \\| '__| |/ /")
    print(" | |  | | | (_| | | | | | |  __/\\ V  V / (_) | |  |   < ")
    print(" |_|  |_|  \\__,_|_| |_| |_|\\___| \\_/\\_/ \\___/|_|  |_|\\_\\")

    print()

    while True:
        print("\n=== Advanced Security Toolkit ===")
        print("1. Attacks")
        print("2. StiganoMessenger")
        print("3. Digital Forensics")
        print("4. OSINT and Information Gathering")
        print("5. Exit")

        choice = input("Select a category (1-5): ")

        if choice == '1':
            attacks_menu()
        elif choice == '2':
            steganography_menu()
        elif choice == '3':
            digital_forensics_menu()
        elif choice == '4':
            osint_menu()
        elif choice == '5':
            print("\nExiting. Goodbye!")
            sys.exit(0)
        else:
            print("\n[!] Invalid selection.")


if __name__ == "__main__":
    main()
