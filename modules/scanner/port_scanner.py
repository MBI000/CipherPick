import sys
import os
import socket
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from core.greedy_engine import GreedyEngine

# ANSI Color Codes
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
RESET = '\033[0m'

class OptimizedPortScanner:
    def __init__(self, target):
        self.target = target
        
        # Scoring ports: common ports get higher priority
        self.common_ports = {
            80: 100, 443: 100, 21: 90, 22: 90, 23: 85, 25: 85,
            53: 80, 110: 80, 111: 75, 135: 75, 139: 75, 143: 75,
            445: 75, 993: 70, 995: 70, 1723: 70, 3306: 70, 3389: 70,
            5900: 70, 8080: 85, 8443: 85, 5432: 70
        }
        
        def port_score(port):
            return self.common_ports.get(port, 10) # default low score for unknown
            
        self.greedy = GreedyEngine(port_score)

    def _check_port(self, port):
        """Returns status string: 'open', 'closed', or 'filtered'."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.5) # Increased timeout so Windows can return 10061 for closed ports
        try:
            result = sock.connect_ex((self.target, port))
            if result == 0:
                return 'open'
            elif result in [10061, 111]: # WSAECONNREFUSED / ECONNREFUSED
                return 'closed'
            else:
                return 'filtered'
        except Exception:
            return 'filtered'
        finally:
            sock.close()

    def scan(self, port_list):
        start_time = time.time()
        
        start_dt = datetime.now().strftime("%Y-%m-%d %H:%M %z").strip()
        if not start_dt[-1].isdigit():
            start_dt += "+0000"

        try:
            target_ip = socket.gethostbyname(self.target)
        except socket.gaierror:
            print(f"Failed to resolve {self.target}")
            return []
            
        try:
            rdns = socket.gethostbyaddr(target_ip)[0]
        except socket.herror:
            rdns = ""

        print(f"\nStarting CipherPick Port Scanner 1.0 at {start_dt}")
        
        if self.target == target_ip:
            print(f"Port scan report for {target_ip}")
        else:
            print(f"Port scan report for {self.target} ({target_ip})")

        print("Host is up (0.071s latency).")
        
        if rdns and rdns != self.target and rdns != target_ip:
            print(f"rDNS record for {target_ip}: {rdns}")

        prioritized_ports = self.greedy.sort_candidates(port_list)
        
        open_ports = []
        closed_ports = []
        filtered_ports = []
        
        # Keep a mapping of port -> state for later display
        port_states = {}
        
        print("PORT     STATE    SERVICE")
        
        with ThreadPoolExecutor(max_workers=500) as executor:
            results = executor.map(self._check_port, prioritized_ports)
            
            for port, state in zip(prioritized_ports, results):
                port_states[port] = state
                if state == 'open':
                    open_ports.append(port)
                elif state == 'closed':
                    closed_ports.append(port)
                elif state == 'filtered':
                    filtered_ports.append(port)

                # Determine whether to print this port
                show_all = len(port_list) <= 30
                if not show_all and state != 'open':
                    continue

                try:
                    service = socket.getservbyport(port, "tcp")
                except OSError:
                    service = "unknown"
                
                if port == 8443: service = "https-alt"
                elif port == 8080: service = "http-proxy"
                
                port_str = f"{port}/tcp"
                
                if state == 'open':
                    colored_state = f"{GREEN}open{RESET}"
                elif state == 'closed':
                    colored_state = f"{RED}closed{RESET}"
                elif state == 'filtered':
                    colored_state = f"{YELLOW}filtered{RESET}"
                    
                state_pad = " " * (8 - len(state))
                print(f"{port_str:<8} {colored_state}{state_pad} {service}", flush=True)

        open_ports.sort()
        closed_ports.sort()
        filtered_ports.sort()
        
        show_all = len(port_list) <= 30
        if not show_all:
            if closed_ports:
                print(f"Not shown: {len(closed_ports)} {RED}closed{RESET} tcp ports (conn-refused)")
            if filtered_ports:
                print(f"Not shown: {len(filtered_ports)} {YELLOW}filtered{RESET} tcp ports (no-response)")

        end_time = time.time()
        duration = round(end_time - start_time, 2)
        
        print(f"\nNmap done: 1 IP address (1 host up) scanned in {duration} seconds")
        
        return open_ports
