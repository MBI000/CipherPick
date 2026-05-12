# CipherPick Framework - Pseudocode

This document outlines the high-level pseudocode for the `main.py` entry point of the CipherPick project, demonstrating the flow of execution and how different modules are integrated via the CLI menus.

## Main Execution Loop

```text
FUNCTION main():
    PRINT ASCII Art Banner
    
    WHILE True (infinite loop):
        PRINT "=== Advanced Security Toolkit ==="
        PRINT "1. Attacks"
        PRINT "2. StiganoMessenger"
        PRINT "3. Digital Forensics"
        PRINT "4. OSINT and Information Gathering"
        PRINT "5. Exit"
        
        PROMPT user for 'choice'
        
        IF choice == '1':
            CALL attacks_menu()
        ELSE IF choice == '2':
            CALL steganography_menu()
        ELSE IF choice == '3':
            CALL digital_forensics_menu()
        ELSE IF choice == '4':
            CALL osint_menu()
        ELSE IF choice == '5':
            PRINT "Exiting. Goodbye!"
            EXIT program with status 0
        ELSE:
            PRINT "[!] Invalid selection."
```

## 1. Attacks Menu

```text
FUNCTION attacks_menu():
    WHILE True:
        PRINT "--- Attacks Menu ---"
        PRINT "1. PDF Password Recovery"
        PRINT "2. MITM (Man-In-The-Middle) Interception"
        PRINT "3. Zphisher (Automated Phishing Tool)"
        PRINT "4. Back to Main Menu"
        
        PROMPT user for 'choice'
        
        IF choice == '1':
            CALL recover_pdf_password()
            
        ELSE IF choice == '2':
            PRINT "[+] Launching Evilginx 3 and ARP Poisoner..."
            PROMPT user for 'target_ip'
            
            SPAWN new process for Evilginx 3 console
            
            IF target_ip is provided:
                PROMPT user for 'gateway_ip'
                PROMPT user for 'interface'
                
                INITIALIZE ArpPoisoner(target_ip, gateway_ip, interface)
                START ArpPoisoner in background
                PRINT "[+] ARP Poisoning active."
                
                WAIT in infinite loop until KeyboardInterrupt (Ctrl+C)
                ON KeyboardInterrupt:
                    STOP ArpPoisoner
            ELSE:
                PRINT "[*] Skipped ARP poisoning. Evilginx 3 running standalone."
                
        ELSE IF choice == '3':
            CHECK if Zphisher directory exists
            IF exists:
                SPAWN new terminal process running Bash and Zphisher
            ELSE:
                PRINT "[!] Zphisher is not installed correctly."
                
        ELSE IF choice == '4':
            BREAK loop (Returns to Main Menu)
            
        ELSE:
            PRINT "[!] Invalid selection."

FUNCTION recover_pdf_password():
    PROMPT user for 'pdf_path'
    PROMPT user for 'wordlist_path'
    
    IF files do not exist:
        PRINT error and RETURN
        
    OPEN wordlist_path for reading:
        FOR EACH password in wordlist:
            TRY:
                OPEN pdf_path using current password
                IF successful:
                    PRINT "[+] SUCCESS! Password is: " + password
                    RETURN
            CATCH PasswordError:
                CONTINUE to next password
            CATCH Other Exception:
                PRINT error and RETURN
                
    PRINT "[-] Password not found in wordlist."
```

## 2. Steganography Menu (StiganoMessenger)

```text
FUNCTION steganography_menu():
    WHILE True:
        PRINT "--- StiganoMessenger ---"
        PRINT "1. Encode Text in Text (Zero-Width XOR)"
        PRINT "2. Decode Text from Text (Zero-Width XOR)"
        PRINT "3. Encode Text in Image (1-Bit LSB)"
        PRINT "4. Decode Text from Image (1-Bit LSB)"
        PRINT "5. Encode Image in Image (4-Bit LSB/MSB)"
        PRINT "6. Decode Image from Image (4-Bit LSB/MSB)"
        PRINT "7. Back to Main Menu"
        
        PROMPT user for 'choice'
        
        IF choice == '1':
            CALL TextSteganography.encode()
        ELSE IF choice == '2':
            CALL TextSteganography.decode()
        ELSE IF choice == '3':
            CALL ImageSteganography.encode_text()
        ELSE IF choice == '4':
            CALL ImageSteganography.decode_text()
        ELSE IF choice == '5':
            CALL ImageSteganography.encode_image()
        ELSE IF choice == '6':
            CALL ImageSteganography.decode_image()
        ELSE IF choice == '7':
            BREAK loop (Returns to Main Menu)
        ELSE:
            PRINT "[!] Invalid selection."
```

## 3. Digital Forensics Menu

```text
FUNCTION digital_forensics_menu():
    WHILE True:
        PRINT "--- Digital Forensics ---"
        PRINT "1. Full File Analysis (Hashes, Signature, Entropy)"
        PRINT "2. Extract Strings from Binary"
        PRINT "3. Recursive Directory & File Scanner"
        PRINT "4. Back to Main Menu"
        
        PROMPT user for 'choice'
        
        IF choice == '1' OR choice == '2':
            PROMPT user for 'filepath'
            IF choice == '1':
                CALL InvestigationTool.analyze_file(filepath)
            ELSE IF choice == '2':
                CALL InvestigationTool.extract_strings(filepath)
                
        ELSE IF choice == '3':
            PROMPT user for 'root' directory path
            INITIALIZE DirectoryScanner(root)
            CALL DirectoryScanner.scan()
            
        ELSE IF choice == '4':
            BREAK loop (Returns to Main Menu)
            
        ELSE:
            PRINT "[!] Invalid selection."
```

## 4. OSINT and Information Gathering Menu

```text
FUNCTION osint_menu():
    WHILE True:
        PRINT "--- OSINT and Information Gathering ---"
        PRINT "1. SQL Injector"
        PRINT "2. Port Scanner"
        PRINT "3. Username Hunter"
        PRINT "4. Back to Main Menu"
        
        PROMPT user for 'choice'
        
        IF choice == '1':
            PROMPT user for target 'url'
            PRINT "[+] Starting SQLMap..."
            RUN SUBPROCESS: python "modules/sqlmap-master/sqlmap.py" -u url --batch
            
        ELSE IF choice == '2':
            CALL PortScanner.advanced_scan()
            
        ELSE IF choice == '3':
            PROMPT user for target 'username'
            INITIALIZE UsernameHunter(username)
            CALL UsernameHunter.hunt()
            
        ELSE IF choice == '4':
            BREAK loop (Returns to Main Menu)
            
        ELSE:
            PRINT "[!] Invalid selection."
```
