import os
import json
import ipaddress
from PyQt5.QtWidgets import QWidget, QVBoxLayout
from PyQt5.QtCore import QUrl
from PyQt5.QtWebEngineWidgets import QWebEngineView

class TopologyWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(400)
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)
        
        # Initialize WebEngineView
        self.graph_view = QWebEngineView()
        self.graph_view.setStyleSheet("background-color: #0a0a0c;")
        self.graph_ready = False
        
        # Load graph.html
        html_path = os.path.join(os.path.dirname(__file__), "assets", "graph.html")
        self.graph_view.load(QUrl.fromLocalFile(html_path))
        self.graph_view.loadFinished.connect(self._on_graph_loaded)
        
        self.layout.addWidget(self.graph_view)
        
    def _on_graph_loaded(self, ok):
        self.graph_ready = True
        if hasattr(self, '_pending_graph_data'):
            self.update_topology(self._pending_graph_data)

    def _build_topology(self, hosts: list) -> dict:
        gateway_ip = None
        gateway_candidates = []

        for host in hosts:
            ip = host.get("ip", "")
            hostname = (host.get("hostname") or "").lower()
            vendor = (host.get("vendor") or "").lower()
            if hostname in ("router", "gateway", "_gateway", "default-gateway"):
                gateway_ip = ip
                break
            if ip.endswith(".1") or ip.endswith(".254"):
                gateway_candidates.insert(0, ip) if ip.endswith(".1") else gateway_candidates.append(ip)

        if not gateway_ip and gateway_candidates:
            gateway_ip = gateway_candidates[0]

        subnets_map = {}
        for host in hosts:
            ip = host.get("ip", "")
            # Try to guess subnet if not provided by doing /24 of IP
            try:
                ip_obj = ipaddress.ip_address(ip)
                if isinstance(ip_obj, ipaddress.IPv4Address):
                    network_str = f"{ip.rsplit('.', 1)[0]}.0/24"
                    if network_str not in subnets_map:
                        net = ipaddress.ip_network(network_str, strict=False)
                        subnets_map[network_str] = {
                            "network": network_str,
                            "prefix": str(net.prefixlen),
                            "broadcast": str(net.broadcast_address),
                            "devices": [],
                        }
                    subnets_map[network_str]["devices"].append(ip)
            except Exception:
                pass
                
        intermediate_vendors = [
            "cisco", "mikrotik", "ubiquiti", "tp-link", "netgear", "dlink",
            "linksys", "tenda", "zyxel", "aruba", "juniper", "fortinet",
            "ruckus", "meraki", "extreme", "huawei", "h3c", "brocade",
        ]
        intermediate_hostnames = [
            "router", "ap", "wifi", "switch", "hub", "access-point",
            "access_point", "wlan", "gateway", "firewall", "proxy",
        ]

        intermediate_ips = set()
        for host in hosts:
            ip = host.get("ip", "")
            if ip == gateway_ip:
                continue
            vendor = (host.get("vendor") or "").lower()
            hostname = (host.get("hostname") or "").lower()
            if any(k in vendor for k in intermediate_vendors):
                intermediate_ips.add(ip)
                continue
            if any(k in hostname for k in intermediate_hostnames):
                intermediate_ips.add(ip)

        edges = []
        if gateway_ip:
            edges.append({"src": gateway_ip, "dst": "internet", "type": "uplink"})

        for host in hosts:
            ip = host.get("ip", "")
            if ip == gateway_ip:
                continue
            if not gateway_ip:
                continue
            if ip in intermediate_ips:
                edges.append({"src": ip, "dst": gateway_ip, "type": "backbone"})
            else:
                parent = gateway_ip
                for inter_ip in intermediate_ips:
                    inter_host = next((h for h in hosts if h.get("ip") == inter_ip), None)
                    if not inter_host:
                        continue
                    inter_vendor = (inter_host.get("vendor") or "").lower()
                    inter_hostname = (inter_host.get("hostname") or "").lower()
                    if any(k in inter_vendor for k in ["tp-link", "netgear", "dlink", "linksys",
                                                        "tenda", "zyxel", "aruba", "ubiquiti",
                                                        "ruckus", "meraki"]) or \
                       any(k in inter_hostname for k in ["ap", "wifi", "wlan", "access"]):
                        try:
                            host_net = ipaddress.ip_address(ip)
                            inter_net = ipaddress.ip_address(inter_ip)
                            host_parts = str(host_net).split(".")
                            inter_parts = str(inter_net).split(".")
                            if host_parts[:3] == inter_parts[:3]:
                                parent = inter_ip
                                break
                        except Exception:
                            pass
                edges.append({"src": ip, "dst": parent, "type": "client"})

        # Get first subnet as main subnet
        subnet_str = list(subnets_map.keys())[0] if subnets_map else ""

        return {
            "devices": hosts,
            "gateway": gateway_ip,
            "subnet": subnet_str,
            "subnets": list(subnets_map.values()),
            "edges": edges,
            "intermediates": list(intermediate_ips),
        }

    def update_topology(self, hosts: list):
        if not self.graph_ready:
            self._pending_graph_data = hosts
            return
        if not hosts:
            return
            
        topology = self._build_topology(hosts)
        data = json.dumps(topology)
        safe_data = json.dumps(data)
        self.graph_view.page().runJavaScript(f"updateGraph({safe_data})")

