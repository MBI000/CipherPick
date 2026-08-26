"""
CipherPick V2 — Local Scanner vs Shodan Correlation Engine
Correlates local subnet scan observations with Shodan internet intelligence.
"""
from typing import Dict, Any, List

class ScannerCorrelationEngine:
    @staticmethod
    def correlate_host(local_host_dict: Dict[str, Any], shodan_host_obj: Any) -> Dict[str, Any]:
        """
        Compares local observation data with Shodan intelligence.
        Returns a structured discrepancy report.
        """
        ip = local_host_dict.get("ip", "Unknown")
        local_open_ports = set()
        
        # Local ports parsing
        if "ports" in local_host_dict and isinstance(local_host_dict["ports"], list):
            for p in local_host_dict["ports"]:
                if isinstance(p, dict):
                    local_open_ports.add(p.get("port"))
                elif isinstance(p, int):
                    local_open_ports.add(p)
        
        shodan_open_ports = set(getattr(shodan_host_obj, "open_ports", []))
        
        matched_ports = local_open_ports.intersection(shodan_open_ports)
        local_only_ports = local_open_ports - shodan_open_ports
        shodan_only_ports = shodan_open_ports - local_open_ports
        
        port_comparisons = []
        
        for p in sorted(matched_ports):
            port_comparisons.append({
                "port": p,
                "local_status": "OPEN (Local Probe)",
                "shodan_status": f"OBSERVED ({getattr(shodan_host_obj, 'last_update', 'Recently')})",
                "discrepancy": "No discrepancy (Concurrence)"
            })
            
        for p in sorted(local_only_ports):
            port_comparisons.append({
                "port": p,
                "local_status": "OPEN (Local Probe)",
                "shodan_status": "NOT OBSERVED IN SHODAN",
                "discrepancy": "Internal service or filtered externally"
            })
            
        for p in sorted(shodan_only_ports):
            port_comparisons.append({
                "port": p,
                "local_status": "CLOSED / NOT DETECTED LOCALLY",
                "shodan_status": f"OBSERVED ({getattr(shodan_host_obj, 'last_update', 'Historically')})",
                "discrepancy": "Exposed on WAN interface or changed status"
            })

        return {
            "ip": ip,
            "local_hostname": local_host_dict.get("hostname", "N/A"),
            "shodan_org": getattr(shodan_host_obj, "org", "N/A"),
            "shodan_location": f"{getattr(shodan_host_obj, 'city', '')}, {getattr(shodan_host_obj, 'country_name', '')}".strip(", "),
            "port_comparisons": port_comparisons,
            "shodan_vulns": getattr(shodan_host_obj, "vulns", []),
            "source_labels": {
                "local": "SOURCE: LOCAL SCANNER (Active Probe)",
                "shodan": "SOURCE: SHODAN (Passive Internet Intelligence)"
            }
        }
