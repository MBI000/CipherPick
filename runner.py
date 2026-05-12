import sys
import os
import json

# Force unbuffered stdout so every print() goes to the log file immediately
sys.stdout.reconfigure(line_buffering=True)

sys.path.append(os.path.abspath(os.path.dirname(__file__)))

def main():
    if len(sys.argv) < 3:
        print("Usage: runner.py <TaskType> <JSON_Kwargs>", flush=True)
        sys.exit(1)
        
    task_type = sys.argv[1]
    kwargs = json.loads(sys.argv[2])
    
    if task_type == "UsernameHunter":
        try:
            from modules.osint.username_hunter import UsernameHunter
            UsernameHunter(kwargs['username']).hunt()
        except Exception as e:
            print(f"\033[91m[-] Error running UsernameHunter: {e}\033[0m", flush=True)
            
    elif task_type == "OptimizedPortScanner":
        try:
            from modules.scanner.port_scanner import OptimizedPortScanner, _colorize_stream_line
            import subprocess
            print("\033[1;36m### Phase 1 · Socket Scan (CipherPick native) ###\033[0m", flush=True)
            OptimizedPortScanner(kwargs['target']).scan(kwargs['port_list'], only_open=kwargs['only_open'])
            print("\n\033[1;36m### Phase 2 · NMAP Aggressive Scan (nmap -A -vv) ###\033[0m", flush=True)
            cmd = ['nmap', '-A', '-vv', kwargs['target']]
            if kwargs['ports'] == "all": cmd.extend(['-p-'])
            elif kwargs['ports'] not in ["common", "custom"]: cmd.extend(['-p', kwargs['ports'].replace(" ", ",")])
            if kwargs['only_open']: cmd.append('--open')
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            for line in iter(process.stdout.readline, ''):
                sys.stdout.write(_colorize_stream_line(line))
                sys.stdout.flush()
            process.stdout.close()
            process.wait()
        except Exception as e:
            print(f"\033[91m[-] Error running PortScanner: {e}\033[0m", flush=True)
            
    elif task_type == "DirectoryScanner":
        try:
            from engine import DirectoryScanner
            DirectoryScanner(kwargs['root']).scan()
        except Exception as e:
            print(f"\033[91m[-] Error running DirectoryScanner: {e}\033[0m", flush=True)
            
    elif task_type == "PDFRecovery":
        try:
            import pikepdf
            pdf_path = kwargs['pdf_path']
            wordlist_path = kwargs['wordlist_path']
            found = False
            
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as words:
                for line in words:
                    password = line.strip()
                    try:
                        with pikepdf.open(pdf_path, password=password) as pdf:
                            print(f"[\033[92m+\033[0m] SUCCESS: Password match found -> \033[92m{password}\033[0m", flush=True)
                            found = True
                            break
                    except pikepdf.PasswordError:
                        print(f"[\033[91m-\033[0m] Failed: \033[91m{password}\033[0m", flush=True)
            if not found:
                print("[\033[91m-\033[0m] Finished: Password not found in the wordlist.", flush=True)
        except ImportError:
            print("\033[91m[-] Error: pikepdf module not installed. Run: pip install pikepdf\033[0m", flush=True)
        except Exception as e:
            print(f"\033[91m[-] Error during PDF Recovery: {e}\033[0m", flush=True)

if __name__ == "__main__":
    main()
