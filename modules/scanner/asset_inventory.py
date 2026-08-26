"""
CipherPick-V2 — Host Discovery & Asset Inventory Engine
Builds on L0p4Map subnet_scanner to provide persistent asset inventory,
risk evaluation, and historical scan comparison.
"""
import os
import sys
import json
import time
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
from modules.scanner.subnet_scanner import scan_network, get_local_subnet, get_vendor

ASSET_FILE = os.path.join(".cipherpick_logs", "asset_inventory.json")

HIGH_RISK_PORTS = {
    445: ("SMB", "High", "Exposed SMB protocol susceptible to remote exploitation (e.g. EternalBlue/MS17-010)."),
    139: ("NetBIOS-SSN", "High", "NetBIOS Session Service exposed to local network enumeration."),
    21:  ("FTP", "High", "Clear-text File Transfer Protocol. Anonymous login or credential sniffing risk."),
    23:  ("Telnet", "Critical", "Unencrypted remote management protocol. Credentials transmitted in clear text."),
    3389: ("RDP", "High", "Remote Desktop Protocol exposed to brute-force attacks and BlueKeep."),
    5900: ("VNC", "High", "Virtual Network Computing remote access service exposed."),
    1433: ("MSSQL", "High", "Microsoft SQL Server exposed directly to the network."),
    3306: ("MySQL", "Medium", "MySQL Database server exposed directly to the network."),
    5432: ("PostgreSQL", "Medium", "PostgreSQL Database server exposed to network traffic."),
    27017: ("MongoDB", "High", "MongoDB NoSQL database exposed without default authentication."),
    6379: ("Redis", "High", "Redis in-memory store exposed without authentication."),
    80:   ("HTTP", "Medium", "Unencrypted Web Server (HTTP) without HTTPS enforced.")
}

def calculate_host_risk(open_ports: list[int], os_hint: str = "") -> tuple[str, list[dict]]:
    """Calculates composite risk level and identifies high risk findings per host."""
    findings = []
    max_severity_weight = 0
    weights = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
    
    for port in open_ports:
        if port in HIGH_RISK_PORTS:
            service, severity, desc = HIGH_RISK_PORTS[port]
            w = weights.get(severity, 1)
            if w > max_severity_weight:
                max_severity_weight = w
            findings.append({
                "port": port,
                "service": service,
                "severity": severity,
                "description": desc
            })
            
    if max_severity_weight == 4:
        overall_risk = "Critical Risk"
    elif max_severity_weight == 3:
        overall_risk = "High Risk"
    elif max_severity_weight == 2:
        overall_risk = "Medium Risk"
    elif open_ports:
        overall_risk = "Low Risk"
    else:
        overall_risk = "Informational"
        
    return overall_risk, findings

class AssetInventory:
    def __init__(self, storage_file: str = ASSET_FILE):
        self.storage_file = storage_file
        os.makedirs(os.path.dirname(self.storage_file), exist_ok=True)
        self.data = self._load_data()

    def _load_data(self) -> dict:
        if os.path.exists(self.storage_file):
            try:
                with open(self.storage_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception:
                pass
        return {"snapshots": [], "current_assets": {}}

    def _save_data(self):
        with open(self.storage_file, 'w', encoding='utf-8') as f:
            json.dump(self.data, f, indent=2)

    def discover_and_save(self, subnet: str = None) -> list[dict]:
        if not subnet:
            try:
                subnet = get_local_subnet()
            except Exception:
                subnet = "192.168.1.0/24"
                
        raw_hosts = scan_network(subnet)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        snapshot_hosts = []
        
        for host in raw_hosts:
            ip = host.get("ip")
            os_hint = host.get("os_hint", "Unknown OS")
            if "windows" in os_hint.lower():
                display_os = "Windows"
            elif "linux" in os_hint.lower():
                display_os = "Linux"
            elif "macos" in os_hint.lower():
                display_os = "macOS"
            elif "network" in os_hint.lower():
                display_os = "Network Device"
            else:
                display_os = "Unknown OS"

            open_ports = host.get("open_ports", [])
            risk_level, findings = calculate_host_risk(open_ports, os_hint)
            
            # Format primary service string: e.g. 192.168.1.10 → Windows → SMB → 445 → High Risk
            primary_service = "None"
            primary_port = "-"
            for p in open_ports:
                if p in HIGH_RISK_PORTS:
                    primary_service = HIGH_RISK_PORTS[p][0]
                    primary_port = str(p)
                    break
            if primary_service == "None" and open_ports:
                primary_port = str(open_ports[0])
                primary_service = f"Port-{primary_port}"

            asset_record = {
                "ip": ip,
                "mac": host.get("mac", "N/A"),
                "vendor": host.get("vendor", "Unknown"),
                "hostname": host.get("hostname", ip),
                "os": display_os,
                "os_hint": os_hint,
                "role": host.get("role", "unknown"),
                "open_ports": open_ports,
                "primary_service": primary_service,
                "primary_port": primary_port,
                "risk_level": risk_level,
                "risk_findings": findings,
                "last_seen": timestamp,
                "summary": f"{ip} → {display_os} → {primary_service} → {primary_port} → {risk_level}"
            }
            snapshot_hosts.append(asset_record)
            self.data["current_assets"][ip] = asset_record

        snapshot_entry = {
            "timestamp": timestamp,
            "subnet": subnet,
            "host_count": len(snapshot_hosts),
            "hosts": snapshot_hosts
        }
        self.data["snapshots"].append(snapshot_entry)
        self._save_data()
        return snapshot_hosts

    def compare_scans(self, snapshot_idx1: int = -2, snapshot_idx2: int = -1) -> dict:
        """Compares two historical scan snapshots to detect network changes over time."""
        snapshots = self.data.get("snapshots", [])
        if len(snapshots) < 2:
            return {"error": "At least 2 scan snapshots are required to perform a comparison."}

        try:
            snap1 = snapshots[snapshot_idx1]
            snap2 = snapshots[snapshot_idx2]
        except IndexError:
            return {"error": "Invalid snapshot index for comparison."}

        hosts1 = {h["ip"]: h for h in snap1.get("hosts", [])}
        hosts2 = {h["ip"]: h for h in snap2.get("hosts", [])}

        new_hosts = [h for ip, h in hosts2.items() if ip not in hosts1]
        removed_hosts = [h for ip, h in hosts1.items() if ip not in hosts2]
        modified_hosts = []

        for ip in hosts2:
            if ip in hosts1:
                ports1 = set(hosts1[ip].get("open_ports", []))
                ports2 = set(hosts2[ip].get("open_ports", []))
                new_ports = list(ports2 - ports1)
                closed_ports = list(ports1 - ports2)
                
                if new_ports or closed_ports:
                    modified_hosts.append({
                        "ip": ip,
                        "hostname": hosts2[ip].get("hostname"),
                        "new_ports": new_ports,
                        "closed_ports": closed_ports,
                        "old_risk": hosts1[ip].get("risk_level"),
                        "new_risk": hosts2[ip].get("risk_level")
                    })

        return {
            "time1": snap1.get("timestamp"),
            "time2": snap2.get("timestamp"),
            "new_hosts": new_hosts,
            "removed_hosts": removed_hosts,
            "modified_hosts": modified_hosts
        }

if __name__ == "__main__":
    inventory = AssetInventory()
    print("[*] Starting Host Discovery & Asset Inventory scan...")
    assets = inventory.discover_and_save()
    print(f"[+] Discovered {len(assets)} hosts:\n")
    for a in assets:
        print(f"  • {a['summary']}")
