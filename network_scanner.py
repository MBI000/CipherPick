"""
CipherPick — Network Scanner Screen
Zenmap-style UI with real background scanning via runner.py / OptimizedPortScanner.
"""
import os
import sys
import json
import subprocess
import time
import re
import streamlit as st
import pandas as pd

# ─────────────────────────────────────────────────────────────────────────────
#  PROFILE → COMMAND MAP
# ─────────────────────────────────────────────────────────────────────────────
PROFILE_COMMANDS = {
    "Intense scan":                "cipherpick -T4 -A -v",
    "Intense scan plus UDP":       "cipherpick -sS -sU -T4 -A -v",
    "Intense scan, all TCP ports": "cipherpick -p 1-65535 -T4 -A -v",
    "Intense scan, no ping":       "cipherpick -T4 -A -v -Pn",
    "Ping scan":                   "cipherpick -sn",
    "Quick scan":                  "cipherpick -T4 -F",
    "Quick scan plus":             "cipherpick -sV -T4 -O -F --version-light",
    "Quick traceroute":            "cipherpick -sn --traceroute",
    "Regular scan":                "cipherpick",
    "Slow comprehensive scan":     "cipherpick -sS -sU -T2 -A -v -PE -PP -PS80,443",
    "L0p4Map Subnet Discovery":    "cipherpick -sn -T4 (Subnet)"
}

PROFILE_PORTS = {
    "Intense scan":                "common",
    "Intense scan plus UDP":       "common",
    "Intense scan, all TCP ports": "all",
    "Intense scan, no ping":       "common",
    "Ping scan":                   "common",
    "Quick scan":                  "common",
    "Quick scan plus":             "common",
    "Quick traceroute":            "common",
    "Regular scan":                "common",
    "Slow comprehensive scan":     "all",
    "L0p4Map Subnet Discovery":    "none"
}

COMMON_PORTS = [80, 443, 21, 22, 23, 25, 53, 110, 111, 135,
                139, 143, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]

# ─────────────────────────────────────────────────────────────────────────────
#  MOCK / INITIAL DATA
# ─────────────────────────────────────────────────────────────────────────────
_MOCK_HOSTS = {
    "lms.rst.edu.eg": {
        "ip": "82.165.196.199", "os_icon": "🐧", "status": "up",
        "open_ports": 4, "filtered_ports": 996, "closed_ports": 0,
        "scanned_ports": 1000, "uptime": "47 days",
        "last_boot": "2025-03-27 08:14", "ipv4": "82.165.196.199",
        "ipv6": "N/A", "mac": "N/A",
        "hostname": "lms.rst.edu.eg", "hostname_type": "user",
        "ports": [
            {"port": "22",   "protocol": "tcp", "state": "open", "service": "ssh",      "version": "OpenSSH 8.2p1"},
            {"port": "80",   "protocol": "tcp", "state": "open", "service": "http",     "version": "nginx 1.18.0"},
            {"port": "443",  "protocol": "tcp", "state": "open", "service": "https",    "version": "nginx 1.18.0 (SSL)"},
            {"port": "8080", "protocol": "tcp", "state": "open", "service": "http-alt", "version": "Apache Tomcat 9.0"},
        ],
        "raw_output": (
            "Starting CipherPick 1.0 at 2025-05-13 22:00 EET\n"
            "Scanning lms.rst.edu.eg (82.165.196.199) [1000 ports]\n"
            "Discovered open port 443/tcp on 82.165.196.199\n"
            "Discovered open port 80/tcp  on 82.165.196.199\n"
            "Discovered open port 22/tcp  on 82.165.196.199\n"
            "Discovered open port 8080/tcp on 82.165.196.199\n"
            "Completed SYN Stealth Scan in 4.23s\n\n"
            "PORT     STATE  SERVICE    VERSION\n"
            "22/tcp   open   ssh        OpenSSH 8.2p1\n"
            "80/tcp   open   http       nginx 1.18.0\n"
            "443/tcp  open   https      nginx 1.18.0 (SSL)\n"
            "8080/tcp open   http-alt   Apache Tomcat 9.0\n\n"
            "CipherPick done: 1 IP address (1 host up) scanned in 19.87 seconds\n"
        ),
    },
}

# ─────────────────────────────────────────────────────────────────────────────
#  CSS
# ─────────────────────────────────────────────────────────────────────────────
_CSS = """
<style>
.detail-card {
    background: rgba(0,242,255,0.04);
    border: 1px solid rgba(0,242,255,0.15);
    border-radius: 8px;
    padding: 14px 18px;
    margin-bottom: 10px;
}
.detail-card h4 {
    font-family: 'Courier New', monospace;
    color: #00f2ff !important;
    font-size: 12px !important;
    letter-spacing: 2px;
    text-transform: uppercase;
    margin: 0 0 8px 0;
    border-bottom: 1px solid rgba(0,242,255,0.15);
    padding-bottom: 6px;
}
.kv-row { display:flex; justify-content:space-between; margin:4px 0;
          font-family:'Courier New',monospace; font-size:13px; }
.kv-key { color: #8b9bab; }
.kv-val { color: #c9d1d9; font-weight:600; }
.scan-row {
    font-family: 'Courier New', monospace; font-size: 12px;
    padding: 8px 12px; border-radius: 6px; margin-bottom: 4px;
    background: rgba(252,226,5,0.06); border: 1px solid rgba(252,226,5,0.15);
    color: #fce205; word-break: break-all;
}
.cmd-bar {
    font-family: 'Courier New', monospace; background: #0a0a0c;
    border: 1px solid #30363d; border-radius: 6px;
    padding: 8px 14px; color: #00f2ff; font-size: 13px;
    letter-spacing: 0.5px; margin-top: 4px; word-break: break-all;
}
.host-item {
    display: flex; align-items: center; gap: 8px;
    padding: 7px 10px; border-radius: 6px;
    font-family: 'Courier New', monospace; font-size: 13px;
    color: #8b9bab; border: 1px solid transparent; margin-bottom: 4px;
}
.host-item.selected {
    background: rgba(0,242,255,0.10);
    border-color: rgba(0,242,255,0.35); color: #00f2ff;
}
</style>
"""

# ─────────────────────────────────────────────────────────────────────────────
#  BACKGROUND TASK HELPERS  (mirrors app.py's pattern)
# ─────────────────────────────────────────────────────────────────────────────
TASK_ID = "network_scanner"

def _get_task():
    return st.session_state.get("tasks", {}).get(TASK_ID)

def _start_scan(target: str, ports: str, only_open: bool):
    if "tasks" not in st.session_state:
        st.session_state.tasks = {}
    os.makedirs(".cipherpick_logs", exist_ok=True)
    log_path = f".cipherpick_logs/{TASK_ID}.log"
    with open(log_path, "w") as f:
        f.write("")
    log_file = open(log_path, "w", buffering=1, encoding="utf-8")

    if ports == "none":
        kwargs = json.dumps({"subnet": target})
        cmd = [sys.executable, "runner.py", "SubnetScan", kwargs]
    else:
        if ports == "all":
            port_list = list(range(1, 65536))
        else:
            port_list = COMMON_PORTS

        kwargs = json.dumps({
            "target": target,
            "ports": ports,
            "port_list": port_list,
            "only_open": only_open,
        })
        cmd = [sys.executable, "runner.py", "OptimizedPortScanner", kwargs]
        
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    process = subprocess.Popen(
        cmd, stdout=log_file, stderr=subprocess.STDOUT, env=env
    )
    st.session_state.tasks[TASK_ID] = {
        "process": process,
        "log_path": log_path,
        "log_file": log_file,
        "target": target,
    }

def _stop_scan():
    task = _get_task()
    if task:
        if task["process"].poll() is None:
            task["process"].terminate()
        if not task["log_file"].closed:
            task["log_file"].close()
        del st.session_state.tasks[TASK_ID]

def _read_log(log_path: str) -> str:
    try:
        with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:
        return ""

def _strip_ansi(text: str) -> str:
    return re.sub(r"\033\[[0-9;]*m", "", text)

def _parse_ports_from_log(log_text: str) -> list[dict]:
    """Extract PORT/STATE/SERVICE rows from scanner output."""
    rows = []
    for line in log_text.splitlines():
        m = re.match(r"^(\d+/\w+)\s+(open|closed|filtered)\s+(\S+)", _strip_ansi(line))
        if m:
            port_proto, state, service = m.group(1), m.group(2), m.group(3)
            rows.append({
                "port": port_proto.split("/")[0],
                "protocol": port_proto.split("/")[1],
                "state": state,
                "service": service,
                "version": "",
            })
    return rows

# ─────────────────────────────────────────────────────────────────────────────
#  ANSI → HTML  (for the Output tab)
# ─────────────────────────────────────────────────────────────────────────────
_ANSI_MAP = {
    "92": "color:#00ff00;", "91": "color:#ff003c;", "93": "color:#fce205;",
    "96": "color:#00f2ff;", "95": "color:#d122e3;", "94": "color:#025cf7;",
    "32": "color:#00ff00;", "31": "color:#ff003c;", "33": "color:#fce205;",
    "36": "color:#00f2ff;", "35": "color:#d122e3;", "34": "color:#025cf7;",
    "37": "color:#ffffff;", "1":  "font-weight:bold;",
}

def _ansi_to_html(text: str) -> str:
    html = ""
    parts = re.split(r"\033\[([0-9;]*)m", text)
    depth = 0
    for i, part in enumerate(parts):
        if i % 2 == 0:
            html += part.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        else:
            codes = part.split(";")
            if "0" in codes or part in ("", "0"):
                html += "</span>" * depth; depth = 0
            else:
                style = "".join(_ANSI_MAP.get(c, "") for c in codes)
                if style:
                    html += f'<span style="{style}">'; depth += 1
    html += "</span>" * depth
    return (
        '<div style="font-family:\'Courier New\',monospace;background:#0a0a0c;'
        'color:#c9d1d9;padding:15px;border-radius:8px;border:1px solid #30363d;'
        'overflow:auto;max-height:480px;white-space:pre;line-height:1.5;">'
        + html + "</div>"
    )

# ─────────────────────────────────────────────────────────────────────────────
#  MAIN ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────
def render():
    st.markdown(_CSS, unsafe_allow_html=True)

    # ── Session defaults ─────────────────────────────────────────────────────
    ss = st.session_state
    ss.setdefault("ns_selected_host", "lms.rst.edu.eg")
    ss.setdefault("ns_target",        "lms.rst.edu.eg")
    ss.setdefault("ns_profile",       "Intense scan")
    ss.setdefault("ns_only_open",     True)
    ss.setdefault("ns_scan_history",  ["Unsaved  cipherpick -T4 -A -v lms.rst.edu.eg"])
    ss.setdefault("ns_hosts",         dict(_MOCK_HOSTS))
    ss.setdefault("ns_filter",        "")

    # ── Header ───────────────────────────────────────────────────────────────
    st.markdown(
        f"""
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
            <div style="font-family:'Courier New',monospace;font-size:10px;
                        color:#445566;letter-spacing:2px;text-transform:uppercase;">
                ● Network Scanner — Zenmap Interface
            </div>
            <button onclick="window.parent.document.querySelector('[data-testid=\\'stSidebarCollapseButton\\']')?.click() || window.parent.document.querySelector('[data-testid=\\'collapsedControl\\']')?.click()" 
                    style="background:transparent; border:1px solid #00f2ff; color:#00f2ff; padding:4px 10px; border-radius:4px; cursor:pointer; font-family:'Courier New',monospace; font-size:10px; transition:all 0.3s ease;" 
                    onmouseover="this.style.background='#00f2ff'; this.style.color='#080c12'; this.style.boxShadow='0 0 10px #00f2ff';" 
                    onmouseout="this.style.background='transparent'; this.style.color='#00f2ff'; this.style.boxShadow='none';">
                ⛶ Toggle Full Screen
            </button>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # ── TOP CONTROL PANEL ────────────────────────────────────────────────────
    task = _get_task()
    is_running = task is not None and task["process"].poll() is None

    c1, c2, c3, c4 = st.columns([3, 2.5, 0.8, 0.8])
    with c1:
        history = list(ss.ns_hosts.keys())
        if ss.ns_target not in history:
            history.insert(0, ss.ns_target)
        target = st.selectbox("Target:", history,
                              index=history.index(ss.ns_target),
                              key="ns_target_sel")
        ss.ns_target = target

    with c2:
        profiles = list(PROFILE_COMMANDS.keys())
        profile = st.selectbox("Profile:", profiles,
                               index=profiles.index(ss.ns_profile),
                               key="ns_profile_sel")
        ss.ns_profile = profile

    with c3:
        st.write("")
        scan_clicked = st.button(
            "⏳ Running…" if is_running else "🔍 Scan",
            key="ns_scan_btn",
            use_container_width=True,
            disabled=is_running,
        )

    with c4:
        st.write("")
        cancel_clicked = st.button("✖ Cancel", key="ns_cancel_btn",
                                   use_container_width=True,
                                   disabled=not is_running)

    base_cmd = PROFILE_COMMANDS.get(profile, "cipherpick")
    full_cmd  = f"{base_cmd} {target}"
    st.markdown(
        '<div style="font-size:11px;color:#445566;margin-top:6px;'
        'font-family:\'Courier New\',monospace;">Command:</div>'
        f'<div class="cmd-bar">⟩ {full_cmd}</div>',
        unsafe_allow_html=True,
    )

    # ── Scan / Cancel actions ─────────────────────────────────────────────────
    if scan_clicked and not is_running:
        ports = PROFILE_PORTS.get(profile, "common")
        _start_scan(target, ports, ss.ns_only_open)
        entry = f"Unsaved  {full_cmd}"
        if entry not in ss.ns_scan_history:
            ss.ns_scan_history.insert(0, entry)
        ss.ns_selected_host = target
        if target not in ss.ns_hosts:
            ss.ns_hosts[target] = {
                "ip": target, "os_icon": "🖥", "status": "up",
                "open_ports": 0, "filtered_ports": 0, "closed_ports": 0,
                "scanned_ports": 0, "uptime": "N/A", "last_boot": "N/A",
                "ipv4": target, "ipv6": "N/A", "mac": "N/A",
                "hostname": target, "hostname_type": "user",
                "ports": [], "raw_output": "",
            }
        st.rerun()

    if cancel_clicked and is_running:
        _stop_scan()
        st.rerun()

    st.markdown('<div style="height:10px"></div>', unsafe_allow_html=True)

    # ── Refresh live scan results into session state ───────────────────────────
    task = _get_task()
    if task:
        raw_log = _read_log(task["log_path"])
        tgt = task.get("target", ss.ns_target)
        if tgt in ss.ns_hosts:
            ss.ns_hosts[tgt]["raw_output"] = raw_log
            parsed = _parse_ports_from_log(raw_log)
            if parsed:
                ss.ns_hosts[tgt]["ports"] = parsed
                ss.ns_hosts[tgt]["open_ports"] = sum(1 for p in parsed if p["state"] == "open")
                ss.ns_hosts[tgt]["filtered_ports"] = sum(1 for p in parsed if p["state"] == "filtered")
                ss.ns_hosts[tgt]["closed_ports"] = sum(1 for p in parsed if p["state"] == "closed")
        # Auto-clear finished task so results persist in host dict
        if task["process"].poll() is not None:
            subnet_res_path = '.cipherpick_logs/subnet_scan_results.json'
            if os.path.exists(subnet_res_path):
                try:
                    with open(subnet_res_path, 'r') as f:
                        hosts = json.load(f)
                    for h in hosts:
                        ip = h.get("ip")
                        ss.ns_hosts[ip] = {
                            "ip": ip,
                            "hostname": h.get("hostname"),
                            "os_icon": "🪟" if "windows" in h.get("os_hint", "").lower() else "🐧" if "linux" in h.get("os_hint", "").lower() else "🍎" if "macos" in h.get("os_hint", "").lower() else "🖥",
                            "status": "up",
                            "open_ports": len(h.get("open_ports", [])),
                            "filtered_ports": 0, "closed_ports": 0, "scanned_ports": 0,
                            "uptime": "N/A", "last_boot": "N/A",
                            "ipv4": ip, "ipv6": "N/A", "mac": h.get("mac"),
                            "hostname_type": "resolved",
                            "ports": [],
                            "raw_output": raw_log,
                            "os": h.get("os", h.get("os_hint")),
                            "role": h.get("role"),
                            "vendor": h.get("vendor"),
                            "risk_level": h.get("risk_level", "Unknown"),
                            "summary": h.get("summary", f"{ip} → {h.get('hostname')}")
                        }
                    os.remove(subnet_res_path)
                except Exception:
                    pass
            _stop_scan()

    # ── MAIN TWO-PANE LAYOUT ─────────────────────────────────────────────────
    left_col, right_col = st.columns([1, 3])

    with left_col:
        h_tab, s_tab = st.tabs(["🖥 Hosts", "🔌 Services"])
        with h_tab:
            _hosts_tab()
        with s_tab:
            _services_tab()

    with right_col:
        tabs = st.tabs([
            "📄 CipherPick Output",
            "🔓 Ports / Hosts",
            "🕸 Topology",
            "🖥 Host Details",
            "📋 Scans",
        ])
        host = ss.ns_hosts.get(ss.ns_selected_host, {})
        task = _get_task()
        is_running = task is not None and task["process"].poll() is None

        with tabs[0]:
            _output_tab(host, is_running, task)
        with tabs[1]:
            _ports_tab(host)
        with tabs[2]:
            _topology_tab()
        with tabs[3]:
            _host_details_tab(host)
        with tabs[4]:
            _scans_tab()


# ─────────────────────────────────────────────────────────────────────────────
#  LEFT PANE
# ─────────────────────────────────────────────────────────────────────────────
def _hosts_tab():
    filt = st.text_input("🔍 Filter Hosts", key="ns_filter_in",
                         placeholder="hostname or IP…")
    st.session_state.ns_filter = filt.lower().strip()
    hosts = st.session_state.ns_hosts
    filtered = {
        k: v for k, v in hosts.items()
        if not st.session_state.ns_filter
        or st.session_state.ns_filter in k.lower()
        or st.session_state.ns_filter in v.get("ip", "").lower()
    }
    if not filtered:
        st.markdown(
            '<div style="color:#445566;font-family:\'Courier New\',monospace;'
            'font-size:12px;padding:8px;">No hosts match filter.</div>',
            unsafe_allow_html=True,
        )
        return

    for hostname, data in filtered.items():
        selected = st.session_state.ns_selected_host == hostname
        css = "host-item selected" if selected else "host-item"
        icon = data.get("os_icon", "🖥")
        ip   = data.get("ip", "")
        col_a, col_b = st.columns([5, 1])
        with col_a:
            st.markdown(
                f'<div class="{css}">{icon} <span style="color:#c9d1d9">{hostname}</span>'
                f'<br><span style="font-size:11px;color:#445566;margin-left:20px">({ip})</span></div>',
                unsafe_allow_html=True,
            )
        with col_b:
            dot = "🟢" if data.get("status") == "up" else "🔴"
            if st.button(dot, key=f"ns_sel_{hostname}", help=f"Select {hostname}"):
                st.session_state.ns_selected_host = hostname
                st.rerun()


def _services_tab():
    hosts = st.session_state.ns_hosts
    rows = []
    for hostname, data in hosts.items():
        for p in data.get("ports", []):
            rows.append({"Service": p["service"], "Port": p["port"],
                         "Protocol": p["protocol"], "Host": hostname})
    if rows:
        st.dataframe(pd.DataFrame(rows).sort_values("Service"),
                     use_container_width=True, hide_index=True)
    else:
        st.info("No services discovered yet.")


# ─────────────────────────────────────────────────────────────────────────────
#  RIGHT PANE TABS
# ─────────────────────────────────────────────────────────────────────────────
def _output_tab(host: dict, is_running: bool, task):
    if is_running and task:
        raw_log = _read_log(task["log_path"])
        st.markdown(
            '<div style="color:#fce205;font-family:\'Courier New\',monospace;'
            'font-size:12px;margin-bottom:6px;">⏳ Scan in progress…</div>',
            unsafe_allow_html=True,
        )
        st.markdown(_ansi_to_html(raw_log or "Waiting for output…"),
                    unsafe_allow_html=True)
        # Auto-refresh while scanning
        time.sleep(1)
        st.rerun()
    else:
        raw = host.get("raw_output", "No output yet. Run a scan first.")
        st.markdown(_ansi_to_html(raw), unsafe_allow_html=True)


def _ports_tab(host: dict):
    ports = host.get("ports", [])
    if not ports:
        st.info("No ports discovered. Select a host or run a scan.")
        return
    rows = []
    for p in ports:
        dot = "🟢" if p["state"] == "open" else ("🟡" if p["state"] == "filtered" else "🔴")
        rows.append({
            "Port":     f"{dot} {p['port']}",
            "Protocol": p["protocol"],
            "State":    p["state"],
            "Service":  p["service"],
            "Version":  p.get("version", ""),
        })
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)


def _topology_tab():
    st.markdown('<div style="height:20px"></div>', unsafe_allow_html=True)
    st.info(
        "🕸 Network topology visualization goes here.\n\n"
        "In a production build this would render an interactive force-directed "
        "graph of discovered hosts (e.g. using pyvis or plotly)."
    )
    hosts = st.session_state.ns_hosts
    lines = ["         [Internet]", "              |"]
    for h, d in hosts.items():
        lines.append(f"    [{d.get('ip', h):^18}]  ← {h}")
    st.code("\n".join(lines), language="text")


def _host_details_tab(host: dict):
    if not host:
        st.info("Select a host from the left pane.")
        return
    c1, c2 = st.columns(2)
    with c1:
        st.markdown(
            '<div class="detail-card"><h4>Host Status & Inventory</h4>'
            + _kv("State",          f"🟢 {host.get('status','N/A')}")
            + _kv("Risk Level",     f"⚠️ {host.get('risk_level', 'N/A')}")
            + _kv("OS Fingerprint", host.get("os", "N/A"))
            + _kv("Vendor",         host.get("vendor", "N/A"))
            + _kv("Open Ports",     host.get("open_ports", "N/A"))
            + _kv("Filtered Ports", host.get("filtered_ports", "N/A"))
            + _kv("Closed Ports",   host.get("closed_ports", "N/A"))
            + "</div>",
            unsafe_allow_html=True,
        )
    with c2:
        st.markdown(
            '<div class="detail-card"><h4>Addresses</h4>'
            + _kv("IPv4", host.get("ipv4", "N/A"))
            + _kv("IPv6", host.get("ipv6", "N/A"))
            + _kv("MAC",  host.get("mac",  "N/A"))
            + '</div><div class="detail-card" style="margin-top:10px"><h4>Asset Summary</h4>'
            + _kv("Summary", host.get("summary", host.get("hostname", "N/A")))
            + _kv("Hostname", host.get("hostname", "N/A"))
            + _kv("Type", host.get("hostname_type", "N/A"))
            + "</div>",
            unsafe_allow_html=True,
        )
    target_ip = host.get("ip", host.get("ipv4"))
    if target_ip and st.button(f"🔍 Look up {target_ip} in Shodan Intelligence", key=f"shodan_btn_{target_ip}"):
        with st.spinner(f"Querying Shodan Intelligence for {target_ip}..."):
            try:
                from modules.shodan.service import ShodanService
                srv = ShodanService()
                sh_host, findings = srv.host_lookup(target_ip)
                st.success(f"Shodan Data Retrieved for {target_ip}")
                st.markdown(f"**Org:** {sh_host.org} | **ISP:** {sh_host.isp} | **Location:** {sh_host.city}, {sh_host.country_name}")
                st.markdown(f"**Shodan Open Ports:** {sh_host.open_ports}")
                if sh_host.vulns:
                    st.warning(f"**Shodan CVEs:** {', '.join(sh_host.vulns)}")
            except Exception as e:
                st.error(f"Shodan Lookup Error: {e}")


def _kv(key: str, val) -> str:
    return (f'<div class="kv-row">'
            f'<span class="kv-key">{key}</span>'
            f'<span class="kv-val">{val}</span></div>')


def _scans_tab():
    history = st.session_state.get("ns_scan_history", [])
    for entry in history:
        st.markdown(f'<div class="scan-row">📋 {entry}</div>',
                    unsafe_allow_html=True)
    if not history:
        st.info("No scans in history yet.")

    st.markdown('<div style="height:14px"></div>', unsafe_allow_html=True)
    ba, bb, bc = st.columns(3)
    with ba:
        if st.button("➕ Append Scan", key="ns_append", use_container_width=True):
            t = st.session_state.get("ns_target", "")
            p = st.session_state.get("ns_profile", "Intense scan")
            e = f"Unsaved  {PROFILE_COMMANDS.get(p,'cipherpick')} {t}"
            if e not in st.session_state.ns_scan_history:
                st.session_state.ns_scan_history.insert(0, e)
            st.rerun()
    with bb:
        if st.button("➖ Remove Scan", key="ns_remove", use_container_width=True):
            if st.session_state.ns_scan_history:
                st.session_state.ns_scan_history.pop(0)
            st.rerun()
    with bc:
        if st.button("❌ Cancel Scan", key="ns_cancel_tab", use_container_width=True):
            _stop_scan()
            st.rerun()
