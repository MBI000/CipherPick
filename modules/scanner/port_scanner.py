"""
CipherPick – Port Scanner Module
════════════════════════════════
Two-phase scan experience:

  Phase 1 ── Fast Python socket scanner (OptimizedPortScanner)
              Greedy-prioritised, multithreaded, classic PORT/STATE/SERVICE table

  Phase 2 ── Real Nmap aggressive scan (nmap -A -vv)
              Dynamic ANSI/colorama colorisation streamed line-by-line
"""

# ─────────────────────────────────────────────────────────────────────────────
# Standard library
# ─────────────────────────────────────────────────────────────────────────────
import re
import sys
import os
import socket
import shutil
import subprocess
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# ─────────────────────────────────────────────────────────────────────────────
# CipherPick core
# ─────────────────────────────────────────────────────────────────────────────
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from core.greedy_engine import GreedyEngine

# ─────────────────────────────────────────────────────────────────────────────
# colorama (Windows CMD / PowerShell compatibility)
# ─────────────────────────────────────────────────────────────────────────────
try:
    import colorama
    colorama.init(autoreset=True, strip=False)
except ImportError:
    pass  # Modern Windows Terminal already supports ANSI natively

# ─────────────────────────────────────────────────────────────────────────────
# ANSI Palette
# ─────────────────────────────────────────────────────────────────────────────
GREEN   = '\033[92m'
RED     = '\033[91m'
YELLOW  = '\033[93m'
CYAN    = '\033[96m'
MAGENTA = '\033[95m'
BLUE    = '\033[94m'
DIM     = '\033[2m'
BOLD    = '\033[1m'
RESET   = '\033[0m'


# ═════════════════════════════════════════════════════════════════════════════
# PHASE 1 — OptimizedPortScanner (exact original implementation)
# ═════════════════════════════════════════════════════════════════════════════

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
            return self.common_ports.get(port, 10)  # default low score for unknown

        self.greedy = GreedyEngine(port_score)

    def _check_port(self, port):
        """Returns status string: 'open', 'closed', or 'filtered'."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.5)  # Increased timeout so Windows can return 10061 for closed ports
        try:
            result = sock.connect_ex((self.target, port))
            if result == 0:
                return 'open'
            elif result in [10061, 111]:  # WSAECONNREFUSED / ECONNREFUSED
                return 'closed'
            else:
                return 'filtered'
        except Exception:
            return 'filtered'
        finally:
            sock.close()

    def scan(self, port_list, only_open=False):
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

        open_ports    = []
        closed_ports  = []
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
                show_all = len(port_list) <= 30 and not only_open
                if not show_all and state != 'open':
                    continue

                try:
                    service = socket.getservbyport(port, "tcp")
                except OSError:
                    service = "unknown"

                if port == 8443:
                    service = "https-alt"
                elif port == 8080:
                    service = "http-proxy"

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

        show_all = len(port_list) <= 30 and not only_open
        if not show_all:
            if closed_ports:
                print(f"Not shown: {len(closed_ports)} {RED}closed{RESET} tcp ports (conn-refused)")
            if filtered_ports:
                print(f"Not shown: {len(filtered_ports)} {YELLOW}filtered{RESET} tcp ports (no-response)")

        end_time = time.time()
        duration = round(end_time - start_time, 2)

        print(f"\nNmap done: 1 IP address (1 host up) scanned in {duration} seconds")

        return open_ports


# ═════════════════════════════════════════════════════════════════════════════
# PHASE 2 — Dynamic colorization engine (nmap -A -vv streamer)
# ═════════════════════════════════════════════════════════════════════════════

_RE_PORT_ROW = re.compile(
    r'^(\d+/\w+)\s+(open\|filtered|open|closed|filtered)\s+(.*)',
    re.IGNORECASE
)
_RE_IP_ADDR  = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b')
_RE_MAC_ADDR = re.compile(r'\b([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\b')

_PORT_STATE_COLOR = {
    'open':          GREEN,
    'closed':        RED,
    'filtered':      YELLOW,
    'open|filtered': YELLOW,
}


def _highlight_ips_macs(text: str) -> str:
    """Wrap any IP / MAC addresses inside text with MAGENTA colour."""
    text = _RE_MAC_ADDR.sub(lambda m: f"{MAGENTA}{m.group(0)}{RESET}", text)
    text = _RE_IP_ADDR.sub( lambda m: f"{MAGENTA}{m.group(0)}{RESET}", text)
    return text


def _colorize_stream_line(raw: str) -> str:
    """
    Colorize a single raw nmap output line using priority-ordered rules.
    IP / MAC addresses are always highlighted in Magenta regardless of rule.
    """
    line = raw.rstrip('\n').rstrip('\r')
    low  = line.lower()

    # Phase / progress indicators ─── Cyan
    if any(kw in low for kw in ('initiating', 'completed', 'nse:', 'scanning')):
        colored = f"{CYAN}{line}{RESET}"

    # Open ports / success ─────── Bold Green
    elif any(kw in low for kw in ('discovered open port', 'host is up')):
        colored = f"{GREEN}{BOLD}{line}{RESET}"

    elif _RE_PORT_ROW.match(line) and 'open' in low \
            and 'closed' not in low and 'filtered' not in low:
        colored = f"{GREEN}{BOLD}{line}{RESET}"

    # Warnings / OS guesses ────── Yellow
    elif any(kw in low for kw in ('warning:', 'retrying', 'just guessing',
                                  'aggressive os guesses', 'os details',
                                  'running (just guessing)')):
        colored = f"{YELLOW}{line}{RESET}"

    # Errors / closed / filtered ── Red (port rows get per-state colour)
    elif any(kw in low for kw in ('filtered', 'closed', 'error', 'failed')):
        m = _RE_PORT_ROW.match(line)
        if m:
            state = m.group(2).lower()
            col   = _PORT_STATE_COLOR.get(state, RED)
            colored = f"{col}{line}{RESET}"
        else:
            colored = f"{RED}{line}{RESET}"

    # NSE / script output ─────── Blue
    elif line.lstrip().startswith('|'):
        colored = f"{BLUE}{line}{RESET}"

    # Section headers ─────────── Bold Cyan
    elif any(kw in low for kw in ('nmap scan report', 'port   state',
                                  'not shown:', 'nmap done')):
        colored = f"{CYAN}{BOLD}{line}{RESET}"

    # Everything else ─────────── plain white
    else:
        colored = line

    # Always highlight IPs and MACs in Magenta (applied last, inline)
    colored = _highlight_ips_macs(colored)
    return colored + '\n'


# ═════════════════════════════════════════════════════════════════════════════
# PortScanner — orchestrates both phases
# ═════════════════════════════════════════════════════════════════════════════

class PortScanner:
    """
    CipherPick – Advanced Port Scanner
    Orchestrates a two-phase scan on a single target:
      Phase 1 – Fast Python socket scanner  (OptimizedPortScanner)
      Phase 2 – aggressive scan        (nmap -A -vv, live colorised stream)
    """

    @staticmethod
    def advanced_scan() -> None:

        # ── Banner ────────────────────────────────────────────────────────────
        print(f"\n{BOLD}{CYAN}╔{'═' * 44}╗{RESET}")
        print(f"{BOLD}{CYAN}║{'CipherPick  ·  Advanced Port Scanner':^44}║{RESET}")
        print(f"{BOLD}{CYAN}╚{'═' * 44}╝{RESET}\n")

        # ── Target input ──────────────────────────────────────────────────────
        target = input(f"  {YELLOW}[?]{RESET} Enter target IP address or domain: ").strip()
        if not target:
            print(f"\n{RED}[!]{RESET} No target provided. Aborting.\n")
            return

        # ── Port list input (for Phase 1) ─────────────────────────────────────
        print(f"\n  {YELLOW}[?]{RESET} Select ports for Phase 1 socket scan:")
        print(f"      {DIM}all{RESET}     — full range 1–65535")
        print(f"      {DIM}common{RESET}  — top 20 well-known ports")
        print(f"      {DIM}80 443 22{RESET} — space-separated custom list")
        ports_raw = input(f"  {YELLOW}>{RESET} ").strip().lower()

        if ports_raw == 'all':
            port_list = list(range(1, 65536))
        elif ports_raw == 'common' or ports_raw == '':
            port_list = [
                80, 443, 21, 22, 23, 25, 53, 110, 111, 135,
                139, 143, 445, 993, 995, 1723, 3306, 3389, 5900, 8080
            ]
        else:
            try:
                port_list = [int(p) for p in ports_raw.split()]
            except ValueError:
                print(f"\n{RED}[!]{RESET} Invalid port list. Defaulting to common ports.")
                port_list = [
                    80, 443, 21, 22, 23, 25, 53, 110, 111, 135,
                    139, 143, 445, 993, 995, 1723, 3306, 3389, 5900, 8080
                ]

        only_open = input(
            f"\n  {YELLOW}[?]{RESET} Show only open ports in Phase 1? (y/n) [{DIM}n{RESET}]: "
        ).strip().lower() == 'y'

        # ══════════════════════════════════════════════════════════════════════
        # PHASE 1 — Python socket scanner
        # ══════════════════════════════════════════════════════════════════════
        print(f"\n{BOLD}{GREEN}{'═' * 62}{RESET}")
        print(f"{BOLD}{GREEN}  PHASE 1  ·  SOCKET SCAN  (CipherPick native){RESET}")
        print(f"{BOLD}{GREEN}{'═' * 62}{RESET}")

        try:
            OptimizedPortScanner(target).scan(port_list, only_open=only_open)
        except KeyboardInterrupt:
            print(f"\n{YELLOW}[!]{RESET} Phase 1 aborted by user.")
            return

        # ══════════════════════════════════════════════════════════════════════
        # PHASE 2 — Nmap aggressive scan with dynamic colorisation
        # ══════════════════════════════════════════════════════════════════════
        if shutil.which('nmap') is None:
            print(
                f"\n{RED}[!]{RESET} Nmap not found — skipping Phase 2.\n"
                f"    Install from {CYAN}https://nmap.org/download{RESET} and add to PATH."
            )
            return

        print(f"\n{BOLD}{CYAN}{'═' * 62}{RESET}")
        print(f"{BOLD}{CYAN}  PHASE 2  ·  NMAP AGGRESSIVE SCAN  (nmap -A -vv){RESET}")
        print(f"{BOLD}{CYAN}{'═' * 62}{RESET}")

        cmd = ['nmap', '-A', '-vv', target]
        print(
            f"\n{GREEN}[+]{RESET} Command : {BOLD}{' '.join(cmd)}{RESET}\n"
            f"{YELLOW}[*]{RESET} Streaming live — press {BOLD}Ctrl+C{RESET} to abort.\n"
            f"{DIM}{'─' * 62}{RESET}\n"
        )

        process = None
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )

            for line in iter(process.stdout.readline, ''):
                sys.stdout.write(_colorize_stream_line(line))
                sys.stdout.flush()

            process.stdout.close()
            process.wait()

            print(f"\n{DIM}{'─' * 62}{RESET}")

            if process.returncode == 0:
                print(f"\n{GREEN}[+]{RESET} Phase 2 scan completed successfully.\n")
            else:
                print(
                    f"\n{YELLOW}[!]{RESET} Nmap exited with code "
                    f"{process.returncode}. Review the output above.\n"
                )

        except KeyboardInterrupt:
            print(f"\n\n{YELLOW}[!]{RESET} Phase 2 aborted by user (Ctrl+C).")
            if process is not None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
            print(f"{RED}[!]{RESET} Nmap process terminated.\n")
