"""
CipherPick-V2 — Shodan OSINT Scanner Module
Replaces SpiderFoot with Shodan REST API intelligence gathering.
"""
import os
import sys
import json
import socket
import urllib.request
import urllib.parse
from datetime import datetime

SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY", "6apjUWGhpborF2uwaC0AToSg5dVb3OQx")

class ShodanScanner:
    def __init__(self, api_key: str = SHODAN_API_KEY):
        self.api_key = api_key
        self.base_url = "https://api.shodan.io"

    def resolve_target(self, target: str) -> str:
        """Resolves target hostname to IPv4 address if necessary."""
        target = target.strip()
        try:
            # Check if already IP
            socket.inet_aton(target)
            return target
        except socket.error:
            pass
        
        try:
            return socket.gethostbyname(target)
        except Exception as e:
            raise ValueError(f"Could not resolve domain/target '{target}': {e}")

    def get_account_info(self) -> dict:
        """Checks Shodan API key validity and credits."""
        url = f"{self.base_url}/api-info?key={self.api_key}"
        req = urllib.request.Request(url, headers={"User-Agent": "CipherPick-V2"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode('utf-8'))

    def lookup_host(self, target: str) -> dict:
        """Queries Shodan for target host details (ports, banners, vulnerabilities)."""
        ip = self.resolve_target(target)
        print(f"\033[96m[*] Querying Shodan API for IP: {ip} (Target: {target})...\033[0m", flush=True)
        
        url = f"{self.base_url}/shodan/host/{ip}?key={self.api_key}"
        req = urllib.request.Request(url, headers={"User-Agent": "CipherPick-V2"})
        
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                self._format_and_print_host(target, ip, data)
                return data
        except urllib.error.HTTPError as e:
            if e.code == 404:
                print(f"\033[93m[!] No Shodan information found for host {ip}\033[0m", flush=True)
                return {"error": "Host not found in Shodan database"}
            elif e.code == 401:
                print(f"\033[91m[-] Invalid Shodan API Key.\033[0m", flush=True)
                return {"error": "Invalid API key"}
            else:
                print(f"\033[91m[-] Shodan API Error HTTP {e.code}: {e.reason}\033[0m", flush=True)
                return {"error": f"HTTP Error {e.code}"}
        except Exception as e:
            print(f"\033[91m[-] Shodan Lookup failed: {e}\033[0m", flush=True)
            return {"error": str(e)}

    def search_query(self, query: str, limit: int = 10) -> dict:
        """Executes a search query against Shodan database."""
        print(f"\033[96m[*] Executing Shodan Search Query: '{query}'...\033[0m", flush=True)
        encoded_query = urllib.parse.quote(query)
        url = f"{self.base_url}/shodan/host/search?key={self.api_key}&query={encoded_query}"
        req = urllib.request.Request(url, headers={"User-Agent": "CipherPick-V2"})
        
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                total = data.get("total", 0)
                matches = data.get("matches", [])[:limit]
                print(f"\033[92m[+] Found {total} total results for query '{query}' (showing top {len(matches)}):\033[0m\n", flush=True)
                for idx, m in enumerate(matches, 1):
                    ip_str = m.get("ip_str", "N/A")
                    port = m.get("port", "N/A")
                    org = m.get("org", "N/A")
                    country = m.get("location", {}).get("country_name", "N/A")
                    banner = m.get("data", "").strip().split("\n")[0][:80]
                    print(f"  {idx}. \033[96m{ip_str}:{port}\033[0m | Org: {org} | Country: {country}")
                    if banner:
                        print(f"     Banner: {banner}")
                return data
        except Exception as e:
            print(f"\033[91m[-] Shodan Search failed: {e}\033[0m", flush=True)
            return {"error": str(e)}

    def _format_and_print_host(self, target: str, ip: str, data: dict):
        org = data.get("org", "Unknown Org")
        isp = data.get("isp", "Unknown ISP")
        country = data.get("country_name", "Unknown Country")
        city = data.get("city", "Unknown City")
        os_info = data.get("os", "N/A")
        ports = data.get("ports", [])
        hostnames = data.get("hostnames", [])
        vulns = data.get("vulns", [])

        print(f"\033[92m[+] Shodan Intelligence Summary for {target} ({ip})\033[0m", flush=True)
        print(f"    • Organization : \033[96m{org}\033[0m", flush=True)
        print(f"    • ISP          : {isp}", flush=True)
        print(f"    • Location     : {city}, {country}", flush=True)
        print(f"    • OS           : {os_info}", flush=True)
        print(f"    • Hostnames    : {', '.join(hostnames) if hostnames else 'N/A'}", flush=True)
        print(f"    • Open Ports   : \033[93m{', '.join(map(str, ports)) if ports else 'None'}\033[0m", flush=True)
        
        if vulns:
            print(f"    • CVE Vulns    : \033[91m{', '.join(vulns[:10])}\033[0m", flush=True)
            
        services = data.get("data", [])
        if services:
            print(f"\n\033[96m--- Running Services ({len(services)}) ---\033[0m", flush=True)
            for s in services[:10]:
                port = s.get("port")
                proto = s.get("transport", "tcp").upper()
                product = s.get("product", "")
                version = s.get("version", "")
                banner = s.get("data", "").strip().split("\n")[0][:75]
                prod_str = f"{product} {version}".strip() or "Unknown Service"
                print(f"  • \033[93mPort {port}/{proto}\033[0m: {prod_str}")
                if banner:
                    print(f"    Raw Banner: {banner}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        tgt = sys.argv[1]
    else:
        tgt = "8.8.8.8"
    scanner = ShodanScanner()
    scanner.lookup_host(tgt)
