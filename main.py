import sys
import os
import subprocess

from modules.osint.graph_explorer import GraphExplorer
from modules.osint.target_prioritizer import TargetPrioritizer
from modules.password_cracker.generator import AdvancedPasswordGenerator
from modules.password_cracker.smart_brute import SmartPasswordPrioritizer
from modules.scanner.dir_scanner import DirectoryScanner
from modules.scanner.port_scanner import PortScanner
from modules.osint.username_hunter import UsernameHunter
from modules.password_cracker.numeric_attack import NumericAttack
from modules.password_cracker.mask_attack import MaskAttack
from modules.password_cracker.trie_dictionary_attack import TrieDictionaryAttack
from modules.password_cracker.hash_cracker import HashCracker
from modules.password_cracker.frequency_analyzer import FrequencyAnalyzer
from modules.stegano.text_stegano import TextSteganography
from modules.stegano.image_stegano import ImageSteganography
from modules.forensics.investigation_tool import InvestigationTool
from modules.mitm.interceptor import CipherPickMITM
#===========================================
# MENUS
#===========================================
def recover_pdf_password():
    import pikepdf
    pdf_path = input("Enter the full path to your PDF file: ").strip().strip('"')
    wordlist_path = input("Enter the full path to your wordlist (.txt): ").strip().strip('"')

    if not os.path.exists(pdf_path) or not os.path.exists(wordlist_path):
        print("\n[!] Error: One of the file paths provided does not exist. Please check the paths and try again.")
        return

    print(f"\n--- Attempting recovery on: {os.path.basename(pdf_path)} ---")

    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as words:

            for line in words:
                password = line.strip()

                try:
                    with pikepdf.open(pdf_path, password=password) as pdf:
                        print(f"\n[+] SUCCESS!")
                        print(f"[*] Password: {password}")
                        return
                except pikepdf.PasswordError:
                    continue
                except Exception as e:
                    print(f"\n[!] An error occurred during processing: {e}")
                    return

        print("\n[-] Finished: Password not found in the wordlist.")

    except Exception as e:
        print(f"[!] Could not open the wordlist file: {e}")

def attacks_menu():
    while True:
        print("\n--- Attacks Menu ---")
        print("1. PDF Password Recovery")
        print("2. MITM (Man-In-The-Middle) Interception")
        print("3. Zphisher (Automated Phishing Tool)")
        print("4. Back to Main Menu")

        choice = input("Select an attack: ")

        if choice == '1':
            recover_pdf_password()
        elif choice == '2':
            import time
            print("\n[+] Launching Evilginx 3 and ARP Poisoner...")
            target_ip = input("Enter Target IP (leave blank for just Evilginx): ").strip()
            
            try:
                # Start Evilginx 3 in a new interactive Command Prompt window
                evilginx_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "evilginx3-master", "evilginx3-master")
                print("\n[+] Spawning Evilginx 3 console...")
                subprocess.Popen(f'start cmd /k "cd /d {evilginx_dir} && go run main.go -p ./phishlets"', shell=True)
                
                if target_ip:
                    gateway_ip = input("Enter Gateway IP: ").strip()
                    interface = input("Enter Network Interface (e.g., eth0 or Wi-Fi): ").strip()
                    
                    # Start the Python ARP Poisoner in the background
                    from modules.mitm.controller import ArpPoisoner
                    poisoner = ArpPoisoner(target_ip, gateway_ip, interface)
                    poisoner.start()
                    print("[+] ARP Poisoning active. Manage interception in the new Evilginx window.")
                    print("[+] Press Ctrl+C here to stop ARP spoofing and restore network.")
                    
                    while True:
                        time.sleep(1)
                else:
                    print("[*] Skipped ARP poisoning. Evilginx 3 is running standalone in the new window.")
            except KeyboardInterrupt:
                if 'poisoner' in locals():
                    print("\n[*] Stopping ARP Poisoning and restoring network...")
                    poisoner.stop()
            except Exception as e:
                print(f"\n[!] Failed to start MITM: {e}")
        elif choice == '3':
            zphisher_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "modules", "zphisher")
            if not os.path.exists(zphisher_dir):
                print("\n[!] Zphisher is not installed correctly.")
            else:
                print("\n[+] Launching Zphisher...")
                bash_path = "bash"
                if os.name == 'nt':
                    git_bash_path = r"C:\Program Files\Git\bin\bash.exe"
                    if os.path.exists(git_bash_path):
                        bash_path = f'"{git_bash_path}"'
                
                try:
                    # Spawn in a new Command Prompt to render the TUI correctly, run zphisher and wait for keypress on exit
                    command = f'start cmd /c "{bash_path} zphisher && pause"'
                    subprocess.Popen(command, shell=True, cwd=zphisher_dir)
                    print("[+] Zphisher launched in a new window.")
                except Exception as e:
                    print(f"\n[!] Error launching Zphisher: {e}")
        elif choice == '4':
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
            PortScanner.advanced_scan()
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

        choice = input("Select a category: ")

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
