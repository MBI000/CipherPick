"""
CipherPick V2 — Shodan API Provider Architecture
IShodanProvider interface and ShodanApiProvider implementation using REST API with official library fallback.
"""
from abc import ABC, abstractmethod
import json
import urllib.request
import urllib.parse
from typing import Dict, Any, Optional

class IShodanProvider(ABC):
    @abstractmethod
    def get_account_info(self, api_key: str) -> Dict[str, Any]:
        pass

    @abstractmethod
    def search(self, api_key: str, query: str, page: int = 1, limit: int = 100, facets: Optional[str] = None) -> Dict[str, Any]:
        pass

    @abstractmethod
    def count(self, api_key: str, query: str, facets: Optional[str] = None) -> Dict[str, Any]:
        pass

    @abstractmethod
    def stats(self, api_key: str, query: str, facets: str = "country,port,product") -> Dict[str, Any]:
        pass

    @abstractmethod
    def get_host(self, api_key: str, ip: str, history: bool = False) -> Dict[str, Any]:
        pass

    @abstractmethod
    def get_honeyscore(self, api_key: str, ip: str) -> float:
        pass

    @abstractmethod
    def get_my_ip(self, api_key: str) -> str:
        pass

    @abstractmethod
    def submit_scan(self, api_key: str, target: str) -> Dict[str, Any]:
        pass

    @abstractmethod
    def get_scan_status(self, api_key: str, scan_id: str) -> Dict[str, Any]:
        pass

    @abstractmethod
    def list_alerts(self, api_key: str) -> list:
        pass

    @abstractmethod
    def create_alert(self, api_key: str, name: str, net: str) -> Dict[str, Any]:
        pass

    @abstractmethod
    def delete_alert(self, api_key: str, alert_id: str) -> bool:
        pass


class ShodanApiProvider(IShodanProvider):
    BASE_URL = "https://api.shodan.io"

    def _request(self, endpoint: str, api_key: str, params: Optional[Dict[str, str]] = None, method: str = "GET", post_data: Optional[bytes] = None) -> Dict[str, Any]:
        if not api_key:
            raise ValueError("Shodan API key is missing.")
        
        params = params or {}
        params["key"] = api_key
        url = f"{self.BASE_URL}{endpoint}?{urllib.parse.urlencode(params)}"
        
        req = urllib.request.Request(url, headers={"User-Agent": "CipherPick-V2"}, method=method, data=post_data)
        
        try:
            with urllib.request.urlopen(req, timeout=15) as response:
                body = response.read().decode('utf-8')
                if not body.strip():
                    return {}
                return json.loads(body)
        except urllib.error.HTTPError as e:
            err_body = e.read().decode('utf-8')
            try:
                err_json = json.loads(err_body)
                err_msg = err_json.get("error", e.reason)
            except Exception:
                err_msg = e.reason
            raise RuntimeError(f"Shodan API Error ({e.code}): {err_msg}")
        except Exception as e:
            raise RuntimeError(f"Network error querying Shodan API: {e}")

    def get_account_info(self, api_key: str) -> Dict[str, Any]:
        return self._request("/api-info", api_key)

    def search(self, api_key: str, query: str, page: int = 1, limit: int = 100, facets: Optional[str] = None) -> Dict[str, Any]:
        params = {"query": query, "page": str(page)}
        if facets:
            params["facets"] = facets
        return self._request("/shodan/host/search", api_key, params=params)

    def count(self, api_key: str, query: str, facets: Optional[str] = None) -> Dict[str, Any]:
        params = {"query": query}
        if facets:
            params["facets"] = facets
        return self._request("/shodan/host/count", api_key, params=params)

    def stats(self, api_key: str, query: str, facets: str = "country:5,port:5,product:5") -> Dict[str, Any]:
        params = {"query": query, "facets": facets}
        return self._request("/shodan/host/count", api_key, params=params)

    def get_host(self, api_key: str, ip: str, history: bool = False) -> Dict[str, Any]:
        params = {}
        if history:
            params["history"] = "true"
        return self._request(f"/shodan/host/{ip}", api_key, params=params)

    def get_honeyscore(self, api_key: str, ip: str) -> float:
        url = f"https://labs.shodan.io/api/honeyscore/{ip}?key={api_key}"
        req = urllib.request.Request(url, headers={"User-Agent": "CipherPick-V2"})
        try:
            with urllib.request.urlopen(req, timeout=10) as response:
                val = response.read().decode('utf-8').strip()
                return float(val)
        except Exception:
            return 0.0

    def get_my_ip(self, api_key: str) -> str:
        res = self._request("/tools/myip", api_key)
        if isinstance(res, str):
            return res
        return res.get("ip", "N/A") if isinstance(res, dict) else str(res)

    def submit_scan(self, api_key: str, target: str) -> Dict[str, Any]:
        data = urllib.parse.urlencode({"ips": target}).encode('utf-8')
        return self._request("/shodan/scan", api_key, method="POST", post_data=data)

    def get_scan_status(self, api_key: str, scan_id: str) -> Dict[str, Any]:
        return self._request(f"/shodan/scan/{scan_id}", api_key)

    def list_alerts(self, api_key: str) -> list:
        res = self._request("/shodan/alert/info", api_key)
        return res if isinstance(res, list) else []

    def create_alert(self, api_key: str, name: str, net: str) -> Dict[str, Any]:
        payload = json.dumps({"name": name, "filters": {"ip": [net]}}).encode('utf-8')
        return self._request("/shodan/alert", api_key, method="POST", post_data=payload)

    def delete_alert(self, api_key: str, alert_id: str) -> bool:
        try:
            self._request(f"/shodan/alert/{alert_id}", api_key, method="DELETE")
            return True
        except Exception:
            return False
