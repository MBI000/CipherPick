"""
CipherPick — Network Scanner Screen
A Streamlit UI that closely mirrors the classic Zenmap desktop application.
"""
import streamlit as st
import pandas as pd

# ─────────────────────────────────────────────
#  MOCK DATA
# ─────────────────────────────────────────────
MOCK_HOSTS = {
    "lms.rst.edu.eg": {
        "ip": "82.165.196.199",
        "os_icon": "🐧",
        "status": "up",
        "open_ports": 4,
        "filtered_ports": 996,
        "closed_ports": 0,
        "scanned_ports": 1000,
        "uptime": "47 days",
        "last_boot": "2025-03-27 08:14:00",
        "ipv4": "82.165.196.199",
        "ipv6": "N/A",
        "mac": "N/A",
        "hostname": "lms.rst.edu.eg",
        "hostname_type": "user",
        "ports": [
            {"port": "22", "protocol": "tcp", "state": "open", "service": "ssh",   "version": "OpenSSH 8.2p1 Ubuntu 4ubuntu0.5"},
            {"port": "80", "protocol": "tcp", "state": "open", "service": "http",  "version": "nginx 1.18.0"},
            {"port": "443","protocol": "tcp", "state": "open", "service": "https", "version": "nginx 1.18.0 (SSL)"},
            {"port": "8080","protocol":"tcp", "state": "open", "service": "http-alt","version":"Apache Tomcat 9.0"},
        ],
        "raw_output": """\
Starting CipherPick 1.0 ( https://cipherpick.io ) at 2025-05-13 22:00 EET
NSE: Loaded 153 scripts for scanning.
Initiating Ping Scan at 22:00
Scanning lms.rst.edu.eg (82.165.196.199) [4 ports]
Completed Ping Scan at 22:00, 0.18s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 22:00
Completed Parallel DNS resolution of 1 host. at 22:00, 0.02s elapsed
Initiating SYN Stealth Scan at 22:00
Scanning lms.rst.edu.eg (82.165.196.199) [1000 ports]
Discovered open port 443/tcp on 82.165.196.199
Discovered open port 80/tcp on 82.165.196.199
Discovered open port 22/tcp on 82.165.196.199
Discovered open port 8080/tcp on 82.165.196.199
Completed SYN Stealth Scan at 22:01, 4.23s elapsed (1000 total ports)
Initiating Service scan at 22:01
Scanning 4 services on lms.rst.edu.eg (82.165.196.199)
Completed Service scan at 22:01, 11.02s elapsed (4 services on 1 host)
Initiating OS detection (try #1) against lms.rst.edu.eg (82.165.196.199)
NSE: Script scanning 82.165.196.199.
Initiating NSE at 22:01
Completed NSE at 22:01, 1.44s elapsed

CipherPick scan report for lms.rst.edu.eg (82.165.196.199)
Host is up (0.041s latency).
Not shown: 996 filtered tcp ports (no-response)
PORT     STATE  SERVICE    VERSION
22/tcp   open   ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.5
80/tcp   open   http       nginx 1.18.0
443/tcp  open   https      nginx 1.18.0 (SSL)
8080/tcp open   http-alt   Apache Tomcat 9.0
Aggressive OS guesses: Linux 5.4 (93%), Linux 4.15 (89%)
Network Distance: 12 hops

TRACEROUTE (using port 80/tcp)
HOP RTT     ADDRESS
1   1.02ms  192.168.1.1
...
12  41.33ms 82.165.196.199

NSE: Script Post-scanning.
Read data files from: /usr/bin/../share/cipherpick
OS and Service detection performed.
CipherPick done: 1 IP address (1 host up) scanned in 19.87 seconds
           Raw packets sent: 2048 | Rcvd: 14
""",
    },
    "192.168.1.124": {
        "ip": "192.168.1.124",
        "os_icon": "🪟",
        "status": "up",
        "open_ports": 2,
        "filtered_ports": 998,
        "closed_ports": 0,
        "scanned_ports": 1000,
        "uptime": "3 days",
        "last_boot": "2025-05-10 14:30:00",
        "ipv4": "192.168.1.124",
        "ipv6": "fe80::1%eth0",
        "mac": "B4:2E:99:A1:3C:DD",
        "hostname": "DESKTOP-WIN11",
        "hostname_type": "PTR",
        "ports": [
            {"port": "135", "protocol": "tcp", "state": "open", "service": "msrpc",  "version": "Microsoft Windows RPC"},
            {"port": "445", "protocol": "tcp", "state": "open", "service": "smb",    "version": "Windows 11 SMBv3"},
        ],
        "raw_output": """\
Starting CipherPick 1.0 at 2025-05-13 22:05 EET
Scanning 192.168.1.124 [1000 ports]
Discovered open port 135/tcp on 192.168.1.124
Discovered open port 445/tcp on 192.168.1.124
Completed SYN Stealth Scan in 3.11s

CipherPick scan report for 192.168.1.124
Host is up (0.003s latency).
PORT    STATE SERVICE  VERSION
135/tcp open  msrpc    Microsoft Windows RPC
445/tcp open  smb      Windows 11 SMBv3
MAC Address: B4:2E:99:A1:3C:DD
OS: Windows 11 (93%)

CipherPick done: 1 IP address (1 host up) scanned in 8.42 seconds
""",
    },
}

PROFILE_COMMANDS = {
    "Intense scan":                   "cipherpick -T4 -A -v",
    "Intense scan plus UDP":          "cipherpick -sS -sU -T4 -A -v",
    "Intense scan, all TCP ports":    "cipherpick -p 1-65535 -T4 -A -v",
    "Intense scan, no ping":          "cipherpick -T4 -A -v -Pn",
    "Ping scan":                      "cipherpick -sn",
    "Quick scan":                     "cipherpick -T4 -F",
    "Quick scan plus":                "cipherpick -sV -T4 -O -F --version-light",
    "Quick traceroute":               "cipherpick -sn --traceroute",
    "Regular scan":                   "cipherpick",
    "Slow comprehensive scan":        "cipherpick -sS -sU -T2 -A -v -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 --script default or discovery",
}

SCAN_HISTORY = [
    "Unsaved  cipherpick -T4 -A -v lms.rst.edu.eg",
    "Unsaved  cipherpick -T4 -F 192.168.1.0/24",
]

# ─────────────────────────────────────────────
#  CSS
# ─────────────────────────────────────────────
_CSS = """
<style>
/* ── Scanner panel wrapper ─────────────────────────────── */
.scanner-panel {
    background: #0d1117;
    border: 1px solid #21262d;
    border-radius: 8px;
    padding: 14px;
    margin-bottom: 10px;
}
/* ── Host list item ──────────────────────────────────────  */
.host-item {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 7px 10px;
    border-radius: 6px;
    cursor: pointer;
    transition: background 0.2s;
    font-family: 'Courier New', monospace;
    font-size: 13px;
    color: #8b9bab;
    border: 1px solid transparent;
    margin-bottom: 4px;
}
.host-item.selected {
    background: rgba(0,242,255,0.10);
    border-color: rgba(0,242,255,0.35);
    color: #00f2ff;
}
.host-item:hover { background: rgba(0,242,255,0.06); color: #c9d1d9; }
/* ── Detail card ─────────────────────────────────────────  */
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
.kv-row { display:flex; justify-content:space-between; margin:4px 0; font-family:'Courier New',monospace; font-size:13px; }
.kv-key { color: #8b9bab; }
.kv-val { color: #c9d1d9; font-weight:600; }
/* ── Scan history row ────────────────────────────────────  */
.scan-row {
    font-family: 'Courier New', monospace;
    font-size: 12px;
    padding: 8px 12px;
    border-radius: 6px;
    margin-bottom: 4px;
    background: rgba(252,226,5,0.06);
    border: 1px solid rgba(252,226,5,0.15);
    color: #fce205;
    word-break: break-all;
}
/* ── Command bar ─────────────────────────────────────────  */
.cmd-bar {
    font-family: 'Courier New', monospace;
    background: #0a0a0c;
    border: 1px solid #1c2333;
    border-radius: 6px;
    padding: 8px 14px;
    color: #00f2ff;
    font-size: 13px;
    letter-spacing: 0.5px;
    margin-top: 4px;
    word-break: break-all;
}
</style>
"""


# ─────────────────────────────────────────────
#  MAIN ENTRY POINT
# ─────────────────────────────────────────────
def render():
    st.markdown(_CSS, unsafe_allow_html=True)

    # ── Session State Defaults ───────────────────────────────────────────────
    if "ns_selected_host" not in st.session_state:
        st.session_state.ns_selected_host = "lms.rst.edu.eg"
    if "ns_target" not in st.session_state:
        st.session_state.ns_target = "lms.rst.edu.eg"
    if "ns_profile" not in st.session_state:
        st.session_state.ns_profile = "Intense scan"
    if "ns_scan_history" not in st.session_state:
        st.session_state.ns_scan_history = list(SCAN_HISTORY)
    if "ns_scanning" not in st.session_state:
        st.session_state.ns_scanning = False
    if "ns_hosts" not in st.session_state:
        st.session_state.ns_hosts = dict(MOCK_HOSTS)
    if "ns_filter" not in st.session_state:
        st.session_state.ns_filter = ""

    # ── TOP CONTROL PANEL ────────────────────────────────────────────────────
    st.markdown(
        '<div style="font-family:\'Courier New\',monospace;font-size:10px;'
        'color:#445566;letter-spacing:2px;text-transform:uppercase;'
        'margin-bottom:8px;">● Network Scanner — Zenmap Interface</div>',
        unsafe_allow_html=True,
    )

    c1, c2, c3, c4 = st.columns([3, 2.5, 0.8, 0.8])
    with c1:
        target_history = list(st.session_state.ns_hosts.keys())
        if st.session_state.ns_target not in target_history:
            target_history.insert(0, st.session_state.ns_target)
        target = st.selectbox(
            "Target:",
            options=target_history,
            index=target_history.index(st.session_state.ns_target),
            key="ns_target_select",
        )
        st.session_state.ns_target = target

    with c2:
        profile = st.selectbox(
            "Profile:",
            options=list(PROFILE_COMMANDS.keys()),
            index=list(PROFILE_COMMANDS.keys()).index(st.session_state.ns_profile),
            key="ns_profile_select",
        )
        st.session_state.ns_profile = profile

    with c3:
        st.write("")  # vertical spacer to align button with selectboxes
        scan_clicked = st.button("🔍 Scan", key="ns_scan_btn", use_container_width=True)

    with c4:
        st.write("")
        cancel_clicked = st.button("✖ Cancel", key="ns_cancel_btn", use_container_width=True)

    # ── Command Bar ──────────────────────────────────────────────────────────
    base_cmd = PROFILE_COMMANDS.get(profile, "cipherpick")
    full_cmd = f"{base_cmd} {target}"
    st.markdown(
        f'<div style="font-size:11px;color:#445566;margin-top:6px;font-family:\'Courier New\',monospace;">Command:</div>'
        f'<div class="cmd-bar">⟩ {full_cmd}</div>',
        unsafe_allow_html=True,
    )

    # Handle scan / cancel actions
    if scan_clicked:
        entry = f"Unsaved  {full_cmd}"
        if entry not in st.session_state.ns_scan_history:
            st.session_state.ns_scan_history.insert(0, entry)
        st.session_state.ns_scanning = True
        st.rerun()

    if cancel_clicked:
        st.session_state.ns_scanning = False

    st.markdown('<div style="height:14px"></div>', unsafe_allow_html=True)

    # ── MAIN TWO-PANE LAYOUT ─────────────────────────────────────────────────
    left_col, right_col = st.columns([1, 3])

    # ══════════════════════════════════════════
    #  LEFT PANE — HOST NAVIGATION
    # ══════════════════════════════════════════
    with left_col:
        host_tab, svc_tab = st.tabs(["🖥 Hosts", "🔌 Services"])

        # ── Hosts Tab ───────────────────────────────────────────────────────
        with host_tab:
            _render_hosts_tab()

        # ── Services Tab ────────────────────────────────────────────────────
        with svc_tab:
            _render_services_tab()

    # ══════════════════════════════════════════
    #  RIGHT PANE — DETAILED RESULTS
    # ══════════════════════════════════════════
    with right_col:
        tabs = st.tabs([
            "📄 CipherPick Output",
            "🔓 Ports / Hosts",
            "🕸 Topology",
            "🖥 Host Details",
            "📋 Scans",
        ])

        host = st.session_state.ns_hosts.get(st.session_state.ns_selected_host, {})

        with tabs[0]:
            _render_output_tab(host)

        with tabs[1]:
            _render_ports_tab(host)

        with tabs[2]:
            _render_topology_tab()

        with tabs[3]:
            _render_host_details_tab(host)

        with tabs[4]:
            _render_scans_tab()


# ─────────────────────────────────────────────
#  LEFT PANE HELPERS
# ─────────────────────────────────────────────
def _render_hosts_tab():
    filt = st.text_input("🔍 Filter Hosts", key="ns_filter_input", placeholder="hostname or IP…")
    st.session_state.ns_filter = filt.lower().strip()

    hosts = st.session_state.ns_hosts
    filtered = {
        k: v for k, v in hosts.items()
        if not st.session_state.ns_filter
        or st.session_state.ns_filter in k.lower()
        or st.session_state.ns_filter in v.get("ip", "").lower()
    }

    if not filtered:
        st.markdown('<div style="color:#445566;font-family:\'Courier New\',monospace;font-size:12px;padding:8px;">No hosts match filter.</div>', unsafe_allow_html=True)
        return

    st.markdown('<div style="height:6px"></div>', unsafe_allow_html=True)
    for hostname, data in filtered.items():
        selected = st.session_state.ns_selected_host == hostname
        css_class = "host-item selected" if selected else "host-item"
        icon = data.get("os_icon", "🖥")
        status_dot = "🟢" if data.get("status") == "up" else "🔴"
        label = f"{icon} {hostname}"
        sub = f"({data.get('ip', '')})"

        # Use a button that looks like a list item
        col_a, col_b = st.columns([5, 1])
        with col_a:
            st.markdown(
                f'<div class="{css_class}">'
                f'{icon} <span style="color:#c9d1d9">{hostname}</span>'
                f'<br><span style="font-size:11px;color:#445566;margin-left:20px">{sub}</span>'
                f'</div>',
                unsafe_allow_html=True,
            )
        with col_b:
            if st.button(status_dot, key=f"ns_host_sel_{hostname}", help=f"Select {hostname}"):
                st.session_state.ns_selected_host = hostname
                st.rerun()


def _render_services_tab():
    hosts = st.session_state.ns_hosts
    # Aggregate all services
    rows = []
    for hostname, data in hosts.items():
        for p in data.get("ports", []):
            rows.append({
                "Service": p["service"],
                "Port": p["port"],
                "Protocol": p["protocol"],
                "Host": hostname,
            })
    if rows:
        df = pd.DataFrame(rows).sort_values("Service")
        st.dataframe(df, use_container_width=True, hide_index=True)
    else:
        st.info("No services discovered yet.")


# ─────────────────────────────────────────────
#  RIGHT PANE HELPERS
# ─────────────────────────────────────────────
def _render_output_tab(host: dict):
    raw = host.get("raw_output", "No output available. Run a scan first.")
    st.code(raw, language="bash")


def _render_ports_tab(host: dict):
    ports = host.get("ports", [])
    if not ports:
        st.info("No ports discovered. Select a host or run a scan.")
        return

    rows = []
    for p in ports:
        state_icon = "🟢" if p["state"] == "open" else ("🟡" if p["state"] == "filtered" else "🔴")
        rows.append({
            "Port": f"{state_icon} {p['port']}",
            "Protocol": p["protocol"],
            "State": p["state"],
            "Service": p["service"],
            "Version": p["version"],
        })

    df = pd.DataFrame(rows)
    st.dataframe(
        df,
        use_container_width=True,
        hide_index=True,
        column_config={
            "Port":     st.column_config.TextColumn("Port", width="small"),
            "Protocol": st.column_config.TextColumn("Protocol", width="small"),
            "State":    st.column_config.TextColumn("State", width="small"),
            "Service":  st.column_config.TextColumn("Service", width="medium"),
            "Version":  st.column_config.TextColumn("Version", width="large"),
        },
    )


def _render_topology_tab():
    st.markdown('<div style="height:20px"></div>', unsafe_allow_html=True)
    st.info(
        "🕸 Network topology visualization goes here.\n\n"
        "In a production build this would render an interactive force-directed graph "
        "of discovered hosts and their relationships (e.g. using pyvis or plotly)."
    )
    # Placeholder ASCII art topology
    st.code(
        """\
         [Internet]
              |
        [82.165.196.199]  ← lms.rst.edu.eg
              |
        [192.168.1.124]   ← DESKTOP-WIN11
""",
        language="text",
    )


def _render_host_details_tab(host: dict):
    if not host:
        st.info("Select a host from the left pane to view details.")
        return

    c1, c2 = st.columns(2)

    with c1:
        st.markdown(
            '<div class="detail-card">'
            '<h4>Host Status</h4>'
            f'<div class="kv-row"><span class="kv-key">State</span><span class="kv-val">🟢 {host.get("status","N/A")}</span></div>'
            f'<div class="kv-row"><span class="kv-key">Open Ports</span><span class="kv-val">{host.get("open_ports","N/A")}</span></div>'
            f'<div class="kv-row"><span class="kv-key">Filtered Ports</span><span class="kv-val">{host.get("filtered_ports","N/A")}</span></div>'
            f'<div class="kv-row"><span class="kv-key">Closed Ports</span><span class="kv-val">{host.get("closed_ports","N/A")}</span></div>'
            f'<div class="kv-row"><span class="kv-key">Scanned Ports</span><span class="kv-val">{host.get("scanned_ports","N/A")}</span></div>'
            f'<div class="kv-row"><span class="kv-key">Up Time</span><span class="kv-val">{host.get("uptime","N/A")}</span></div>'
            f'<div class="kv-row"><span class="kv-key">Last Boot</span><span class="kv-val">{host.get("last_boot","N/A")}</span></div>'
            '</div>',
            unsafe_allow_html=True,
        )

    with c2:
        st.markdown(
            '<div class="detail-card">'
            '<h4>Addresses</h4>'
            f'<div class="kv-row"><span class="kv-key">IPv4</span><span class="kv-val">{host.get("ipv4","N/A")}</span></div>'
            f'<div class="kv-row"><span class="kv-key">IPv6</span><span class="kv-val">{host.get("ipv6","N/A")}</span></div>'
            f'<div class="kv-row"><span class="kv-key">MAC</span><span class="kv-val">{host.get("mac","N/A")}</span></div>'
            '</div>'
            '<div class="detail-card" style="margin-top:10px">'
            '<h4>Hostnames</h4>'
            f'<div class="kv-row"><span class="kv-key">Name</span><span class="kv-val">{host.get("hostname","N/A")}</span></div>'
            f'<div class="kv-row"><span class="kv-key">Type</span><span class="kv-val">{host.get("hostname_type","N/A")}</span></div>'
            '</div>',
            unsafe_allow_html=True,
        )


def _render_scans_tab():
    history = st.session_state.get("ns_scan_history", [])
    if not history:
        st.info("No scans in history yet.")
    else:
        for entry in history:
            st.markdown(f'<div class="scan-row">📋 {entry}</div>', unsafe_allow_html=True)

    st.markdown('<div style="height:14px"></div>', unsafe_allow_html=True)
    ba, bb, bc = st.columns([1, 1, 1])
    with ba:
        if st.button("➕ Append Scan", key="ns_append_scan", use_container_width=True):
            target = st.session_state.get("ns_target", "")
            profile = st.session_state.get("ns_profile", "Intense scan")
            cmd = f"{PROFILE_COMMANDS.get(profile, 'cipherpick')} {target}"
            entry = f"Unsaved  {cmd}"
            if entry not in st.session_state.ns_scan_history:
                st.session_state.ns_scan_history.insert(0, entry)
            st.rerun()
    with bb:
        if st.button("➖ Remove Scan", key="ns_remove_scan", use_container_width=True):
            if st.session_state.ns_scan_history:
                st.session_state.ns_scan_history.pop(0)
            st.rerun()
    with bc:
        if st.button("❌ Cancel Scan", key="ns_cancel_scan_tab", use_container_width=True):
            st.session_state.ns_scanning = False
            st.rerun()
