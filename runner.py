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
            from modules.scanner.port_scanner import OptimizedPortScanner
            print("\033[1;36m### Phase 1 · Socket Scan (CipherPick native) ###\033[0m", flush=True)
            res = OptimizedPortScanner(kwargs['target']).scan(kwargs['port_list'], only_open=kwargs['only_open'])
            
            # Save results for GUI
            os.makedirs('.cipherpick_logs', exist_ok=True)
            with open('.cipherpick_logs/net_scan_results.json', 'w') as f:
                json.dump(res, f)
                
        except Exception as e:
            print(f"\033[91m[-] Error running OptimizedPortScanner: {e}\033[0m", flush=True)

    elif task_type == "NmapScan":
        try:
            import subprocess
            import xml.etree.ElementTree as ET
            import shlex
            
            target = kwargs['target']
            flags = kwargs['flags']
            
            os.makedirs('.cipherpick_logs', exist_ok=True)
            xml_path = '.cipherpick_logs/nmap_out.xml'
            
            cmd = ['nmap']
            if flags:
                cmd.extend(shlex.split(flags))
            cmd.extend(['-oX', xml_path, target])
            
            print(f"\033[1;36m### Executing: {' '.join(cmd)} ###\033[0m\n", flush=True)
            
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            raw_output = []
            
            from modules.scanner.port_scanner import _colorize_stream_line
            for line in iter(process.stdout.readline, ''):
                colored_line = _colorize_stream_line(line)
                sys.stdout.write(colored_line)
                sys.stdout.flush()
                raw_output.append(colored_line)
                
            process.wait()
            
            res = {
                "target": target,
                "ip": target,
                "hostname": target,
                "os": "Unknown",
                "os_icon": "🖥",
                "ports": [],
                "raw_output": "".join(raw_output)
            }
            
            if os.path.exists(xml_path):
                tree = ET.parse(xml_path)
                root = tree.getroot()
                
                host = root.find('host')
                if host is not None:
                    addr = host.find('address')
                    if addr is not None:
                        res["ip"] = addr.get('addr', target)
                        
                    # OS detection
                    os_el = host.find('os')
                    if os_el is not None:
                        osmatch = os_el.find('osmatch')
                        if osmatch is not None:
                            res["os"] = osmatch.get('name', 'Unknown')
                            os_lower = res["os"].lower()
                            if "windows" in os_lower: res["os_icon"] = "🪟"
                            elif "linux" in os_lower: res["os_icon"] = "🐧"
                            elif "apple" in os_lower or "macos" in os_lower: res["os_icon"] = "🍎"
                            
                    # Ports
                    ports_el = host.find('ports')
                    if ports_el is not None:
                        for port in ports_el.findall('port'):
                            pnum = port.get('portid', '')
                            proto = port.get('protocol', '')
                            
                            state_el = port.find('state')
                            state = state_el.get('state', 'unknown') if state_el is not None else 'unknown'
                            
                            svc_el = port.find('service')
                            svc = svc_el.get('name', 'unknown') if svc_el is not None else 'unknown'
                            ver = f"{svc_el.get('product', '')} {svc_el.get('version', '')}".strip() if svc_el is not None else ''
                            
                            res["ports"].append({
                                "port": pnum,
                                "protocol": proto,
                                "state": state,
                                "service": svc,
                                "version": ver
                            })
                            
            with open('.cipherpick_logs/net_scan_results.json', 'w') as f:
                json.dump(res, f)
                
            if "vulners" in flags or "vuln" in flags:
                try:
                    from modules.scanner.attack_surface import _parse as parse_cves
                    cve_result = parse_cves(target, xml_path)
                    if cve_result.get("cves"):
                        with open('.cipherpick_logs/attack_surface_results.json', 'w') as f:
                            json.dump(cve_result, f)
                except Exception as e:
                    print(f"Failed to parse CVEs: {e}")
                
        except Exception as e:
            print(f"\033[91m[-] Error running NmapScan: {e}\033[0m", flush=True)

    elif task_type == "SubnetScan":
        try:
            from modules.scanner.asset_inventory import AssetInventory
            subnet = kwargs.get('subnet')
            print(f"\033[1;36m### Host Discovery & Asset Inventory Scan on {subnet or 'Local Subnet'} ###\033[0m", flush=True)
            inventory = AssetInventory()
            snapshot_hosts = inventory.discover_and_save(subnet)
            
            os.makedirs('.cipherpick_logs', exist_ok=True)
            with open('.cipherpick_logs/subnet_scan_results.json', 'w') as f:
                json.dump(snapshot_hosts, f)
                
            print(f"\033[92m[+] Discovered & Indexed {len(snapshot_hosts)} live hosts\033[0m", flush=True)
            for h in snapshot_hosts:
                print(f"  \033[96m• {h['summary']}\033[0m", flush=True)
                print(f"    MAC: {h['mac']} | Vendor: {h['vendor']} | Hostname: {h['hostname']}", flush=True)
        except Exception as e:
            print(f"\033[91m[-] Error running SubnetScan Asset Inventory: {e}\033[0m", flush=True)

    elif task_type == "AttackSurfaceScan":
        try:
            from modules.scanner.attack_surface import scan_attack_surface
            target = kwargs['target']
            print(f"\033[1;36m### L0p4Map Attack Surface Scan on {target} ###\033[0m", flush=True)
            result = scan_attack_surface(target)
            
            log_path = ".cipherpick_logs/attack_surface_results.json"
            os.makedirs(".cipherpick_logs", exist_ok=True)
            with open(log_path, "w") as f:
                json.dump(result, f)
            print(f"Results saved to {log_path}", flush=True)
            sys.exit(0)
        except Exception as e:
            print(f"Attack Surface Scan Error: {e}", flush=True)
            sys.exit(1)
            
    elif task_type == "DirectoryScanner":
        try:
            from engine import DirectoryScanner
            DirectoryScanner(kwargs['root']).scan()
        except Exception as e:
            print(f"\033[91m[-] Error running DirectoryScanner: {e}\033[0m", flush=True)
            
    elif task_type in ("ShodanScan", "SpiderFoot"):
        try:
            from modules.osint.shodan_scanner import ShodanScanner
            target = kwargs['target']
            api_key = kwargs.get('api_key', "6apjUWGhpborF2uwaC0AToSg5dVb3OQx")
            print(f"\033[96m[*] Starting Shodan OSINT Scan for target: {target}\033[0m", flush=True)
            scanner = ShodanScanner(api_key=api_key)
            scanner.lookup_host(target)
        except Exception as e:
            print(f"\033[91m[-] Error running Shodan OSINT scan: {e}\033[0m", flush=True)

    elif task_type == "SSHBruteforce":
        try:
            from modules.password_cracker.ssh_brute import SSHBruteforce
            print(f"\033[96m[*] Starting SSH Bruteforce for: {kwargs.get('host')}\033[0m", flush=True)
            SSHBruteforce(
                host=kwargs.get('host'),
                passlist_path=kwargs.get('passlist'),
                user=kwargs.get('user'),
                userlist_path=kwargs.get('userlist')
            ).execute()
        except ImportError:
            print("\033[91m[-] Error: paramiko module not installed. Run: pip install paramiko\033[0m", flush=True)
        except Exception as e:
            print(f"\033[91m[-] Error running SSHBruteforce: {e}\033[0m", flush=True)

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
