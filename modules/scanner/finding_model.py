"""
CipherPick V2 — Security Finding Normalization Schema
Common internal data model for security findings across Network Scanner, Shodan, Web Scanner, and SQL Injector.
"""
from dataclasses import dataclass, field
from typing import Optional, Dict, Any
from datetime import datetime

@dataclass
class SecurityFinding:
    source: str          # e.g., "LOCAL_SCANNER", "SHODAN", "WEB_SCANNER"
    target: str          # e.g., IP address or domain
    ip: str
    port: int = 0
    protocol: str = "tcp"
    service: str = ""
    product: str = ""
    version: str = ""
    vulnerability: str = "" # e.g., "CVE-2021-44228" or "Exposed Administrative Interface"
    severity: str = "MEDIUM" # LOW, MEDIUM, HIGH, CRITICAL
    confidence: str = "HIGH" # LOW, MEDIUM, HIGH
    evidence: str = ""      # Raw banner or observation string
    first_seen: str = field(default_factory=lambda: datetime.now().isoformat())
    last_seen: str = field(default_factory=lambda: datetime.now().isoformat())
    recommendation: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "ip": self.ip,
            "port": self.port,
            "protocol": self.protocol,
            "service": self.service,
            "product": self.product,
            "version": self.version,
            "vulnerability": self.vulnerability,
            "severity": self.severity,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "recommendation": self.recommendation
        }
