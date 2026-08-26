"""
CipherPick V2 — Shodan High-Level Service
Provides business logic, TTL caching, finding conversion, and credit estimation.
"""
import os
import json
import gzip
import time
from typing import Dict, Any, List, Optional, Tuple

from .config import ShodanConfig
from .provider import IShodanProvider, ShodanApiProvider
from .models import (
    ShodanHost, ShodanService, ShodanSearchResult,
    ShodanAccountInfo, ShodanScan, ShodanAlert
)
from ..scanner.finding_model import SecurityFinding

class ShodanService:
    def __init__(self, provider: Optional[IShodanProvider] = None):
        self.provider = provider or ShodanApiProvider()
        self._cache: Dict[str, Tuple[float, Any]] = {}
        self.cache_ttl = 300 # 5 minutes TTL

    def _get_cached(self, key: str) -> Optional[Any]:
        if key in self._cache:
            ts, val = self._cache[key]
            if time.time() - ts < self.cache_ttl:
                return val
        return None

    def _set_cache(self, key: str, val: Any):
        self._cache[key] = (time.time(), val)

    def get_api_key(self) -> str:
        return ShodanConfig.get_api_key()

    def get_account_info(self) -> ShodanAccountInfo:
        key = self.get_api_key()
        cache_key = f"acc_{key}"
        cached = self._get_cached(cache_key)
        if cached: return cached

        data = self.provider.get_account_info(key)
        info = ShodanAccountInfo(
            plan=data.get("plan", "Basic"),
            query_credits=data.get("query_credits", 0),
            scan_credits=data.get("scan_credits", 0),
            monitored_ips=data.get("monitored_ips", 0),
            unlocked=data.get("unlocked", False),
            https=data.get("https", True),
            raw_data=data
        )
        self._set_cache(cache_key, info)
        return info

    def host_lookup(self, ip: str, history: bool = False) -> Tuple[ShodanHost, List[SecurityFinding]]:
        key = self.get_api_key()
        cache_key = f"host_{ip}_{history}"
        cached = self._get_cached(cache_key)
        if cached: return cached

        data = self.provider.get_host(key, ip, history=history)
        
        services: List[ShodanService] = []
        findings: List[SecurityFinding] = []
        
        for item in data.get("data", []):
            port = item.get("port", 0)
            proto = item.get("transport", "tcp")
            prod = item.get("product", "")
            ver = item.get("version", "")
            banner = item.get("data", "").strip()
            cves = item.get("vulns", [])
            if isinstance(cves, dict):
                cves = list(cves.keys())
            
            services.append(ShodanService(
                port=port, transport=proto, product=prod,
                version=ver, banner=banner[:200], cves=cves
            ))

            # Finding normalization
            sev = "HIGH" if cves or port in [445, 3389, 21, 23] else "MEDIUM" if port in [80, 443, 22] else "LOW"
            rec = f"Investigate public exposure of service {prod} on port {port}."
            if cves:
                rec += f" Apply patches for CVEs: {', '.join(cves[:3])}."

            findings.append(SecurityFinding(
                source="SHODAN",
                target=ip,
                ip=ip,
                port=port,
                protocol=proto,
                service=prod or f"port-{port}",
                product=prod,
                version=ver,
                vulnerability=", ".join(cves) if cves else "Exposed Internet Service",
                severity=sev,
                confidence="HIGH",
                evidence=banner[:150],
                recommendation=rec
            ))

        host = ShodanHost(
            ip=ip,
            org=data.get("org", "Unknown"),
            isp=data.get("isp", "Unknown"),
            country_name=data.get("country_name", "Unknown"),
            city=data.get("city", "Unknown"),
            latitude=data.get("latitude", 0.0),
            longitude=data.get("longitude", 0.0),
            os=data.get("os", "N/A"),
            hostnames=data.get("hostnames", []),
            open_ports=data.get("ports", []),
            services=services,
            vulns=data.get("vulns", []),
            last_update=data.get("last_update", ""),
            raw_data=data
        )

        res = (host, findings)
        self._set_cache(cache_key, res)
        return res

    def search(self, query: str, page: int = 1, limit: int = 100) -> Tuple[ShodanSearchResult, List[SecurityFinding]]:
        key = self.get_api_key()
        raw = self.provider.search(key, query, page=page, limit=limit)
        
        matches = raw.get("matches", [])
        total = raw.get("total", 0)
        facets = raw.get("facets", {})
        
        findings: List[SecurityFinding] = []
        for m in matches:
            ip = m.get("ip_str", "0.0.0.0")
            port = m.get("port", 0)
            proto = m.get("transport", "tcp")
            prod = m.get("product", "")
            ver = m.get("version", "")
            cves = m.get("vulns", [])
            if isinstance(cves, dict):
                cves = list(cves.keys())

            findings.append(SecurityFinding(
                source="SHODAN",
                target=ip,
                ip=ip,
                port=port,
                protocol=proto,
                service=prod or f"port-{port}",
                product=prod,
                version=ver,
                vulnerability=", ".join(cves) if cves else "Exposed Service",
                severity="HIGH" if cves else "MEDIUM",
                confidence="HIGH",
                evidence=m.get("data", "").strip()[:100],
                recommendation=f"Review external access controls for {ip}:{port}"
            ))

        res = ShodanSearchResult(query=query, total=total, matches=matches, facets=facets)
        return res, findings

    def count(self, query: str) -> int:
        key = self.get_api_key()
        res = self.provider.count(key, query)
        return res.get("total", 0)

    def stats(self, query: str, facets: str = "country:5,port:5,product:5") -> Dict[str, Any]:
        key = self.get_api_key()
        res = self.provider.stats(key, query, facets=facets)
        return res.get("facets", {})

    def honeyscore(self, ip: str) -> float:
        key = self.get_api_key()
        return self.provider.get_honeyscore(key, ip)

    def my_ip(self) -> str:
        key = self.get_api_key()
        return self.provider.get_my_ip(key)

    def submit_scan(self, target: str) -> ShodanScan:
        key = self.get_api_key()
        raw = self.provider.submit_scan(key, target)
        return ShodanScan(
            scan_id=raw.get("id", "N/A"),
            target=target,
            status=raw.get("status", "SUBMITTED"),
            created_at=time.strftime("%Y-%m-%d %H:%M:%S"),
            credits_used=raw.get("count", 1)
        )

    def list_alerts(self) -> List[ShodanAlert]:
        key = self.get_api_key()
        raw_list = self.provider.list_alerts(key)
        res = []
        for a in raw_list:
            res.append(ShodanAlert(
                alert_id=a.get("id", ""),
                name=a.get("name", "Alert"),
                target=a.get("filters", {}),
                created_at=a.get("created", ""),
                triggers=list(a.get("triggers", {}).keys())
            ))
        return res

    def create_alert(self, name: str, net: str) -> Dict[str, Any]:
        key = self.get_api_key()
        return self.provider.create_alert(key, name, net)

    def delete_alert(self, alert_id: str) -> bool:
        key = self.get_api_key()
        return self.provider.delete_alert(key, alert_id)

    @staticmethod
    def parse_local_file(file_path: str) -> List[Dict[str, Any]]:
        """Parses local .json or .json.gz Shodan data files safely."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
            
        results = []
        is_gz = file_path.endswith(".gz")
        open_fn = gzip.open if is_gz else open
        
        with open_fn(file_path, "rt", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        results.append(json.loads(line))
                    except Exception:
                        pass
        return results

    @staticmethod
    def convert_to_csv(matches: List[Dict[str, Any]], output_path: str):
        """Converts Shodan matches to CSV format."""
        import csv
        fieldnames = ["ip_str", "port", "transport", "product", "version", "org", "country_name", "hostnames"]
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for m in matches:
                row = {
                    "ip_str": m.get("ip_str", ""),
                    "port": m.get("port", ""),
                    "transport": m.get("transport", ""),
                    "product": m.get("product", ""),
                    "version": m.get("version", ""),
                    "org": m.get("org", ""),
                    "country_name": m.get("location", {}).get("country_name", m.get("country_name", "")),
                    "hostnames": ", ".join(m.get("hostnames", []))
                }
                writer.writerow(row)
