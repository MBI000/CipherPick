import os
import re
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from collections import defaultdict

CVSS_MIN = 4.0
MAX_CVES_PER_PORT = 5
GENERIC_SERVICES = {"tcpwrapped", "unknown", "filtered", ""}
HIGH_RISK_PORTS  = {21,23,25,110,135,139,445,512,513,514,3389,5900,6379,27017}
MEDIUM_RISK_PORTS = {22,80,8080,3306,5432,1433,2375,2376,4444}

def cvss_to_severity(cvss: float) -> str:
    if cvss >= 9.0: return "CRITICAL"
    if cvss >= 7.0: return "HIGH"
    if cvss >= 4.0: return "MEDIUM"
    return "LOW"

def scan_attack_surface(target: str) -> dict:
    tmp = tempfile.NamedTemporaryFile(suffix=".xml", delete=False)
    tmp_path = tmp.name
    tmp.close()

    cmd = [
        "nmap", "-sV", "-O",
        "--script", "vulners",
        "--open", "-Pn", "-T4",
        "-oX", tmp_path,
        target
    ]

    try:
        subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
            check=True
        )
    except Exception as e:
        pass

    result = _parse(target, tmp_path)
    if os.path.exists(tmp_path):
        os.unlink(tmp_path)
    return result

def _parse(target: str, xml_path: str) -> dict:
    result = {
        "target": target,
        "os": "Unknown",
        "ports": [],
        "cves": [],
    }

    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except (ET.ParseError, FileNotFoundError):
        return result

    host = root.find("host")
    if host is None:
        return result

    cpe_list = [cpe.text or "" for cpe in host.findall(".//cpe")]
    is_windows = any("windows" in c for c in cpe_list)
    is_linux   = any("linux"   in c for c in cpe_list)
    is_macos   = any("mac_os"  in c or "macos" in c for c in cpe_list)

    osmatch = host.find(".//osmatch")
    if osmatch is not None:
        os_name  = osmatch.get("name", "")
        accuracy = osmatch.get("accuracy", "?")
        result["os"] = f"{os_name} ({accuracy}%)"
        if not any([is_windows, is_linux, is_macos]):
            osL = os_name.lower()
            is_windows = "windows" in osL
            is_linux   = any(k in osL for k in ["linux","ubuntu","debian"])
            is_macos   = any(k in osL for k in ["mac os","macos","darwin"])

    port_cve_count = defaultdict(int)

    for port in host.findall(".//port"): 
        state = port.find("state")
        if state is None or state.get("state") != "open":
            continue

        portid   = port.get("portid", "?")
        protocol = port.get("protocol", "tcp")
        service  = port.find("service")

        svc_name    = service.get("name",    "-") if service is not None else "-"
        svc_product = service.get("product", "") if service is not None else ""
        svc_version = service.get("version", "") if service is not None else ""
        svc_full    = f"{svc_product} {svc_version}".strip() or "-"
        svc_ostype  = service.get("ostype",  "").lower() if service is not None else ""

        portnum = int(portid)
        if portnum in HIGH_RISK_PORTS:
            risk = "HIGH"
        elif portnum in MEDIUM_RISK_PORTS:
            risk = "MEDIUM"
        else:
            risk = "LOW"

        result["ports"].append({
            "port":     portid,
            "protocol": protocol,
            "service":  svc_name,
            "version":  svc_full,
            "risk":     risk,
        })

        for script in port.findall("script"):
            scriptID = script.get("id", "")
            output   = script.get("output", "")

            if not any(x in scriptID for x in ["vulners", "vuln", "exploit"]):
                continue

            for line in output.splitlines():
                line = line.strip()
                if not line:
                    continue

                match = re.match(r"(CVE-\d{4}-\d+)\s+(\d+\.\d+)\s+https?://", line)
                if not match:
                    continue

                cve_id = match.group(1)
                cvss   = float(match.group(2))

                if cvss < CVSS_MIN:
                    continue

                if svc_name.lower() in GENERIC_SERVICES:
                    continue

                if not svc_product:
                    continue

                if any(c["id"] == cve_id for c in result["cves"]):
                    continue

                if port_cve_count[portid] >= MAX_CVES_PER_PORT:
                    continue

                windows_only = {"netlogon", "msrpc", "microsoft-ds", "ms-wbt-server"}
                if svc_name.lower() in windows_only and not is_windows:
                    continue

                if svc_ostype:
                    if "windows" in svc_ostype and not is_windows:
                        continue
                    if "linux" in svc_ostype and not is_linux:
                        continue

                port_cve_count[portid] += 1
                result["cves"].append({
                    "id":      cve_id,
                    "cvss":    cvss,
                    "port":    portid,
                    "service": svc_name,
                    "detail":  f"{svc_name} {svc_full} — {cve_id}",
                })

    result["cves"].sort(key=lambda c: c["cvss"], reverse=True)

    for port_entry in result["ports"]:
        port_cves = [c for c in result["cves"] if c["port"] == port_entry["port"]]
        if not port_cves:
            continue
        max_cvss = max(c["cvss"] for c in port_cves)
        port_entry["risk"] = cvss_to_severity(max_cvss)

    return result
