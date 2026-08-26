"""
CipherPick V2 — Shodan Data Models
Structured representations of Shodan Host, Search, Account, Scan, Alert, and Stream data.
"""
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

@dataclass
class ShodanService:
    port: int
    transport: str = "tcp"
    product: str = ""
    version: str = ""
    banner: str = ""
    cves: List[str] = field(default_factory=list)
    ssl_subject: Optional[str] = None

@dataclass
class ShodanHost:
    ip: str
    org: str = "Unknown"
    isp: str = "Unknown"
    country_name: str = "Unknown"
    city: str = "Unknown"
    latitude: float = 0.0
    longitude: float = 0.0
    os: str = "N/A"
    hostnames: List[str] = field(default_factory=list)
    open_ports: List[int] = field(default_factory=list)
    services: List[ShodanService] = field(default_factory=list)
    vulns: List[str] = field(default_factory=list)
    last_update: str = ""
    raw_data: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ShodanSearchResult:
    query: str
    total: int
    matches: List[Dict[str, Any]]
    credits_used: int = 1
    facets: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ShodanAccountInfo:
    plan: str = "Free"
    query_credits: int = 0
    scan_credits: int = 0
    monitored_ips: int = 0
    unlocked: bool = False
    https: bool = True
    raw_data: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ShodanScan:
    scan_id: str
    target: str
    status: str = "SUBMITTED"
    created_at: str = ""
    credits_used: int = 1

@dataclass
class ShodanAlert:
    alert_id: str
    name: str
    target: Dict[str, Any]
    created_at: str = ""
    triggers: List[str] = field(default_factory=list)
    notifiers: List[str] = field(default_factory=list)

@dataclass
class ShodanStreamEvent:
    timestamp: str
    ip: str
    port: int
    protocol: str
    org: str
    summary: str
