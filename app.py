import streamlit as st
import os
import sys
import base64
import subprocess
import time
import io
import re
import contextlib
import engine

sys.path.append(os.path.abspath(os.path.dirname(__file__)))

@contextlib.contextmanager
def capture_stdout(placeholder=None, max_lines=15):
    stdout = sys.stdout
    class StreamlitStdout:
        def __init__(self):
            self.full_output = ""
            self.last_update = time.time()
            
        def write(self, text):
            self.full_output += text
            if placeholder and time.time() - self.last_update > 0.1:
                lines = self.full_output.split('\n')
                window = lines[-max_lines:] if max_lines and len(lines) > max_lines else lines
                placeholder.markdown(format_terminal_output('\n'.join(window)), unsafe_allow_html=True)
                self.last_update = time.time()
                
        def flush(self):
            pass
        
        def getvalue(self):
            return self.full_output
            
    streamer = StreamlitStdout()
    sys.stdout = streamer
    try:
        yield streamer
    finally:
        sys.stdout = stdout

def format_terminal_output(text):
    if not text:
        return ""
    
    ansi_mapping = {
        # High Intensity
        '92': 'color: #00ff00;', 
        '91': 'color: #ff003c;', 
        '93': 'color: #fce205;', 
        '96': 'color: #00f2ff;', 
        '95': 'color: #d122e3;', 
        '94': 'color: #025cf7;', 
        
        # Standard Foreground
        '30': 'color: #555555;',
        '31': 'color: #ff003c;',
        '32': 'color: #00ff00;',
        '33': 'color: #fce205;',
        '34': 'color: #025cf7;',
        '35': 'color: #d122e3;',
        '36': 'color: #00f2ff;',
        '37': 'color: #ffffff;',
        
        # Backgrounds
        '40': 'background-color: #000000;',
        '41': 'background-color: #ff003c; color: #ffffff;',
        '42': 'background-color: #00ff00; color: #000000;',
        '43': 'background-color: #fce205; color: #000000;',
        '44': 'background-color: #025cf7; color: #ffffff;',
        '45': 'background-color: #d122e3; color: #ffffff;',
        '46': 'background-color: #00f2ff; color: #000000;',
        '47': 'background-color: #ffffff; color: #000000;',
        
        '1': 'font-weight: bold; text-shadow: 0 0 5px currentColor;',
        '2': 'opacity: 0.7;',
    }
    
    html_out = ""
    parts = re.split(r'\033\[([0-9;]*)m', text)
    span_depth = 0
    
    for i, part in enumerate(parts):
        if i % 2 == 0:
            escaped = part.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
            html_out += escaped
        else:
            codes = part.split(';')
            if '0' in codes or part == '' or part == '0':
                html_out += "</span>" * span_depth
                span_depth = 0
            else:
                style = ""
                for code in codes:
                    if code in ansi_mapping:
                        style += ansi_mapping[code]
                if style:
                    html_out += f'<span style="{style}">'
                    span_depth += 1
            
    html_out += "</span>" * span_depth
    return f'<div style="font-family: \'Courier New\', Courier, monospace; background-color: #0a0a0c; color: #c9d1d9; padding: 15px; border-radius: 8px; border: 1px solid #30363d; overflow-x: auto; overflow-y: auto; max-height: 600px; white-space: pre; line-height: 1.4; margin-bottom: 1rem;">{html_out}</div>'

def render_terminal_output(text):
    if not text:
        return
    st.markdown(format_terminal_output(text), unsafe_allow_html=True)

# --- Background Task Manager ---
import json

def get_task(task_id):
    if 'tasks' not in st.session_state:
        st.session_state.tasks = {}
    return st.session_state.tasks.get(task_id)

def start_task(task_id, cmd, env=None, cwd=None):
    if 'tasks' not in st.session_state:
        st.session_state.tasks = {}
    os.makedirs(".cipherpick_logs", exist_ok=True)
    log_path = f".cipherpick_logs/{task_id}.log"
    with open(log_path, 'w') as f:
        f.write("")
    # line-buffered (buffering=1) so every line is flushed to disk immediately
    log_file = open(log_path, 'w', buffering=1, encoding='utf-8')
    # PYTHONUNBUFFERED forces the subprocess's own stdout to be line-buffered
    proc_env = os.environ.copy()
    if env:
        proc_env.update(env)
    proc_env['PYTHONUNBUFFERED'] = '1'
    process = subprocess.Popen(cmd, stdout=log_file, stderr=subprocess.STDOUT, env=proc_env, cwd=cwd)
    st.session_state.tasks[task_id] = {
        'process': process,
        'log_path': log_path,
        'log_file': log_file
    }

def stop_task(task_id):
    task = get_task(task_id)
    if task:
        if task['process'].poll() is None:
            task['process'].terminate()
        if not task['log_file'].closed:
            task['log_file'].close()
        del st.session_state.tasks[task_id]

def render_running_task(task_id, header, show_stop=True):
    task = get_task(task_id)
    if not task: return False
    
    st.markdown(header)
    col1, col2 = st.columns([4, 1])
    is_running = task['process'].poll() is None
    
    with col2:
        if is_running:
            if show_stop and st.button("Stop & Reset", key=f"stop_{task_id}"):
                stop_task(task_id)
                st.rerun()
        else:
            if st.button("Clear Results", key=f"clear_{task_id}"):
                stop_task(task_id)
                st.rerun()
                
    out_placeholder = st.empty()
    
    last_line_count = 0
    accumulated = []

    def read_new_lines():
        nonlocal last_line_count
        try:
            with open(task['log_path'], 'r', encoding='utf-8', errors='ignore') as f:
                all_lines = f.read().splitlines()
            new = all_lines[last_line_count:]
            if new:
                last_line_count = len(all_lines)
                return new
        except Exception:
            pass
        return []

    # CSS-only blinking cursor — never changes line count, so no layout jump
    CSS_CURSOR = (
        '<style>'
        '@keyframes blink{0%,100%{opacity:1}50%{opacity:0}}'
        '.term-cursor{display:inline-block;width:8px;height:1em;'
        'background:#00ff00;vertical-align:text-bottom;'
        'animation:blink 1s step-start infinite;margin-left:2px;}'
        '</style>'
        '<span class="term-cursor"></span>'
    )

    def render(running=False):
        display = accumulated[-400:] if len(accumulated) > 400 else accumulated
        text = '\n'.join(display)
        inner = format_terminal_output(text)
        if running:
            # Inject cursor inside the terminal div, after the text
            inner = inner.rstrip()
            if inner.endswith('</div>'):
                inner = inner[:-6] + CSS_CURSOR + '</div>'
        out_placeholder.markdown(inner, unsafe_allow_html=True)

    if is_running:
        while task['process'].poll() is None:
            new_lines = read_new_lines()
            if new_lines:
                accumulated.extend(new_lines)
            render(running=True)
            time.sleep(0.15)

    # Drain any remaining lines after process ends
    final_lines = read_new_lines()
    if final_lines:
        accumulated.extend(final_lines)

    render(running=False)
        
    if task['process'].poll() is not None:
        st.markdown(
            '<div style="background:rgba(0,255,0,0.08);color:#00ff00;padding:10px 15px;'
            'border-left:4px solid #00ff00;border-radius:4px;font-family:\'Courier New\',monospace;'
            'margin-top:8px;">[+] Task completed successfully.</div>',
            unsafe_allow_html=True
        )
    
    return True # returning True indicates the UI should NOT show the input form

# --- Backend Imports ---
try:
    from modules.scanner.port_scanner import PortScanner, OptimizedPortScanner
    from modules.stegano.image_stegano import ImageSteganography
    from modules.stegano.text_stegano import TextSteganography
    from modules.password_cracker.numeric_attack import NumericAttack
    from modules.password_cracker.mask_attack import MaskAttack
    from modules.password_cracker.trie_dictionary_attack import TrieDictionaryAttack
    from modules.password_cracker.hash_cracker import HashCracker
    from modules.password_cracker.frequency_analyzer import FrequencyAnalyzer
    from modules.forensics.investigation_tool import InvestigationTool
    from modules.osint.username_hunter import UsernameHunter
    from modules.scanner.dir_scanner import DirectoryScanner
    BACKEND_AVAILABLE = True
except ImportError as e:
    BACKEND_AVAILABLE = False

st.set_page_config(page_title="CipherPick Toolkit", page_icon="🔐", layout="wide")

# --- CSS Injection ---
def inject_custom_css():
    st.markdown("""
        <style>
        /* Base Background */
        .stApp {
            background-color: #0E1117;
            color: #C9D1D9;
        }
        
        /* Headers */
        h1, h2, h3, h4, h5, h6 {
            font-family: 'Courier New', Courier, monospace !important;
            color: #00f2ff !important;
            text-transform: uppercase;
            letter-spacing: 2px;
        }
        
        /* Buttons */
        div.stButton > button {
            background-color: transparent !important;
            color: #00f2ff !important;
            border: 1px solid #00f2ff !important;
            border-radius: 8px !important;
            transition: all 0.3s ease !important;
            font-family: 'Courier New', Courier, monospace !important;
            font-weight: bold !important;
        }
        div.stButton > button:hover {
            background-color: #00f2ff !important;
            color: #0E1117 !important;
            box-shadow: 0 0 15px #00f2ff !important;
            border-color: #00f2ff !important;
        }
        
        /* Text Areas and Inputs */
        textarea, input, .stTextArea textarea, .stTextInput input, .stSelectbox > div > div {
            font-family: 'Courier New', Courier, monospace !important;
            border-radius: 8px !important;
        }
        
        /* File Uploader */
        .stFileUploader > div > div {
            border-radius: 8px !important;
            border: 1px dashed #00f2ff !important;
            background-color: rgba(0, 242, 255, 0.05) !important;
            transition: all 0.3s ease !important;
        }
        .stFileUploader > div > div:hover {
            background-color: rgba(0, 242, 255, 0.1) !important;
            box-shadow: 0 0 10px rgba(0, 242, 255, 0.3) !important;
        }

        /* Alerts and Warnings */
        div[data-baseweb="notification"], .stAlert {
            background-color: rgba(255, 191, 0, 0.1) !important;
            color: #FFBF00 !important;
            border-left: 4px solid #FFBF00 !important;
        }

        div[data-testid="stSidebar"] {
            background-color: #080c12 !important;
            border-right: 1px solid #1c2333 !important;
        }
        div[data-testid="stSidebar"] * {
            font-family: 'Courier New', Courier, monospace !important;
        }
        /* Sidebar radio — hide default styling and replace visually */
        div[data-testid="stSidebar"] .stRadio label {
            display: flex !important;
            align-items: center !important;
            gap: 10px !important;
            padding: 10px 14px !important;
            margin: 3px 0 !important;
            border-radius: 8px !important;
            border: 1px solid transparent !important;
            cursor: pointer !important;
            transition: all 0.25s ease !important;
            color: #8b9bab !important;
            font-size: 13px !important;
            letter-spacing: 0.5px !important;
        }
        div[data-testid="stSidebar"] .stRadio label:hover {
            background: rgba(0, 242, 255, 0.07) !important;
            border-color: rgba(0, 242, 255, 0.3) !important;
            color: #00f2ff !important;
        }
        div[data-testid="stSidebar"] .stRadio label[data-checked="true"],
        div[data-testid="stSidebar"] .stRadio [aria-checked="true"] + label {
            background: rgba(0, 242, 255, 0.12) !important;
            border-color: #00f2ff !important;
            color: #00f2ff !important;
            box-shadow: 0 0 8px rgba(0,242,255,0.15) !important;
        }
        /* hide the actual radio dots */
        div[data-testid="stSidebar"] .stRadio [data-testid="stMarkdownContainer"] p {
            margin: 0 !important;
        }
        .sidebar-badge {
            display: inline-block;
            font-size: 10px;
            padding: 1px 6px;
            border-radius: 99px;
            background: rgba(0,255,0,0.15);
            color: #00ff00;
            border: 1px solid #00ff00;
            margin-left: auto;
            font-family: 'Courier New', monospace;
            animation: pulse 2s infinite;
        }

        /* Custom Header Badge */
        .pulsing-badge {
            display: inline-block;
            width: 12px;
            height: 12px;
            background-color: #00ff00;
            border-radius: 50%;
            margin-right: 8px;
            box-shadow: 0 0 8px #00ff00;
            animation: pulse 1.5s infinite;
        }
        @keyframes pulse {
            0% { box-shadow: 0 0 8px #00ff00; }
            50% { box-shadow: 0 0 16px #00ff00, 0 0 24px #00ff00; }
            100% { box-shadow: 0 0 8px #00ff00; }
        }
        .header-container {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 15px 20px;
            border-bottom: 1px solid #30363d;
            margin-bottom: 30px;
            background: linear-gradient(90deg, rgba(14,17,23,1) 0%, rgba(0,242,255,0.05) 100%);
            border-radius: 8px;
        }
        .header-title {
            font-family: 'Courier New', Courier, monospace;
            color: #00f2ff;
            font-size: 24px;
            font-weight: bold;
            display: flex;
            align-items: center;
            text-shadow: 0 0 5px rgba(0,242,255,0.5);
        }
        .header-status {
            font-family: 'Courier New', Courier, monospace;
            color: #00ff00;
            font-size: 14px;
            display: flex;
            align-items: center;
        }
        </style>
    """, unsafe_allow_html=True)

def render_custom_header():
    pass  # Header removed; branding lives in the sidebar

def render_page_header(section: str, tool: str):
    """Renders a slim, styled header at the top of the main content area."""
    SECTION_ICONS = {
        "Attacks": "⚔️",
        "StiganoMessenger": "🕵️",
        "Digital Forensics": "🔬",
        "OSINT": "🌐",
        "Cryptographic Engine": "🔑",
    }
    icon = SECTION_ICONS.get(section, "🔐")
    st.markdown(
        f'<div style="'
        f'background:linear-gradient(90deg,rgba(0,242,255,0.06) 0%,rgba(0,0,0,0) 100%);'
        f'border-left:3px solid #00f2ff;border-radius:0 6px 6px 0;'
        f'padding:10px 20px;margin-bottom:18px;display:flex;align-items:center;gap:12px;">'
        f'<span style="font-size:22px;">{icon}</span>'
        f'<div>'
        f'<div style="font-family:\'Courier New\',monospace;font-size:10px;color:#445566;'
        f'letter-spacing:2px;text-transform:uppercase;">{section}</div>'
        f'<div style="font-family:\'Courier New\',monospace;font-size:18px;font-weight:bold;'
        f'color:#00f2ff;text-shadow:0 0 8px rgba(0,242,255,0.4);letter-spacing:1px;">{tool}</div>'
        f'</div></div>',
        unsafe_allow_html=True
    )

# --- SCREENS ---

def screen_attacks(option):
    render_page_header("Attacks", option or "Attacks")
    st.markdown("---")
    
    if option == "PDF Password Recovery":
        task_id = "pdf_recovery"
        if not render_running_task(task_id, "### PDF Recovery Background Execution"):
            pdf_path = st.text_input("Enter the full path to your PDF file:").strip().strip('"').strip("'")
            wordlist_path = st.text_input("Enter the full path to your wordlist (.txt):").strip().strip('"').strip("'")
            
            if st.button("Recover Password"):
                if not os.path.exists(pdf_path) or not os.path.exists(wordlist_path):
                    st.error("Error: One of the file paths provided does not exist.")
                else:
                    cmd = [sys.executable, "runner.py", "PDFRecovery", json.dumps({"pdf_path": pdf_path, "wordlist_path": wordlist_path})]
                    start_task(task_id, cmd)
                    st.rerun()
                        
    elif option == "MITM (Man-In-The-Middle) Interception":
        st.warning("Launching Evilginx 3 and ARP Poisoner requires admin privileges and network access.")
        target_ip = st.text_input("Enter Target IP (leave blank for just Evilginx):")
        gateway_ip = st.text_input("Enter Gateway IP:")
        interface = st.text_input("Enter Network Interface (e.g., eth0 or Wi-Fi):")
        
        if st.button("Launch MITM"):
            evilginx_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "evilginx3-master", "evilginx3-master")
            try:
                subprocess.Popen(f'start cmd /k "cd /d {evilginx_dir} && go run main.go -p ./phishlets"', shell=True)
                st.success("Spawning Evilginx 3 console...")
                if target_ip:
                    st.info("To start ARP poisoning, please use the CLI as it requires background daemon management.")
            except Exception as e:
                st.error(f"Failed to start MITM: {e}")
                
    elif option == "Zphisher (Automated Phishing Tool)":
        if st.button("Launch Zphisher"):
            zphisher_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "modules", "zphisher")
            if not os.path.exists(zphisher_dir):
                st.error("Zphisher is not installed correctly.")
            else:
                bash_path = "bash"
                if os.name == 'nt':
                    git_bash_path = r"C:\Program Files\Git\bin\bash.exe"
                    if os.path.exists(git_bash_path):
                        bash_path = f'"{git_bash_path}"'
                try:
                    command = f'start cmd /c "{bash_path} zphisher && pause"'
                    subprocess.Popen(command, shell=True, cwd=zphisher_dir)
                    st.success("Zphisher launched in a new window.")
                except Exception as e:
                    st.error(f"Error launching Zphisher: {e}")
                    
    elif option == "Advanced Password Cracking":
        tgt_entry = st.text_input("Target Hash / File / Text:")
        atk_cb = st.selectbox("Attack Methodology:", ["Numeric", "Mask", "Dictionary", "Hash Crack", "Frequency Analysis"])
        if st.button("Launch Cracker"):
            if not tgt_entry:
                st.error("Target required.")
            else:
                with st.spinner(f"Launching {atk_cb} Attack..."):
                    try:
                        if BACKEND_AVAILABLE:
                            with capture_stdout() as out:
                                if atk_cb == "Numeric":
                                    NumericAttack(tgt_entry, 4).execute()
                                elif atk_cb == "Mask":
                                    MaskAttack(tgt_entry, "?d?d?d?d").execute()
                                elif atk_cb == "Dictionary":
                                    TrieDictionaryAttack(tgt_entry, "passwords.txt").execute()
                                elif atk_cb == "Hash Crack":
                                    HashCracker.crack(tgt_entry, "passwords.txt")
                                elif atk_cb == "Frequency Analysis":
                                    FrequencyAnalyzer.decrypt_caesar(tgt_entry)
                            render_terminal_output(out.getvalue() or "Attack completed. Check console/logs.")
                        else:
                            st.error("Backend modules unavailable.")
                    except Exception as e:
                        st.error(f"Attack Failed: {e}")

def screen_stigano(option):
    render_page_header("StiganoMessenger", option or "StiganoMessenger")
    st.markdown("---")
    
    if BACKEND_AVAILABLE:
        st.info("Execute steganography operations. For file operations, please provide absolute paths.")
        
        cvr_file, sec_file, out_file, enc_key = None, None, None, None
        
        if option == "Encode Text in Text (Zero-Width XOR)":
            cvr_file = st.text_input("Cover Text:")
            sec_file = st.text_input("Secret Text to Hide:")
            enc_key = st.text_input("XOR Encryption Key:")
        elif option == "Decode Text from Text (Zero-Width XOR)":
            cvr_file = st.text_area("Paste Stego-Text:")
            enc_key = st.text_input("XOR Decryption Key:")
        elif option == "Encode Text in Image (1-Bit LSB)":
            cvr_file = st.text_input("Cover Image Path:")
            sec_file = st.text_input("Secret Text to Hide:")
            out_file = st.text_input("Output Image Name (e.g., hidden.png):", value="stego_output.png")
        elif option == "Decode Text from Image (1-Bit LSB)":
            cvr_file = st.text_input("Stego-Image Path:")
        elif option == "Encode Image in Image (4-Bit LSB/MSB)":
            cvr_file = st.text_input("Cover Image Path:")
            sec_file = st.text_input("Secret Image Path:")
            out_file = st.text_input("Output Image Name (e.g., stego.png):", value="stego_output.png")
        elif option == "Decode Image from Image (4-Bit LSB/MSB)":
            cvr_file = st.text_input("Stego-Image Path:")
            out_file = st.text_input("Output Image Name (e.g., extracted.png):", value="extracted_image.png")

        if st.button("Execute"):
            with capture_stdout() as out:
                try:
                    if option == "Encode Text in Text (Zero-Width XOR)":
                        if cvr_file and sec_file and enc_key:
                            TextSteganography.encode(cover_text=cvr_file, secret_text=sec_file, key=enc_key)
                        else:
                            st.error("Please fill all fields.")
                    elif option == "Decode Text from Text (Zero-Width XOR)":
                        if cvr_file and enc_key:
                            TextSteganography.decode(stego_text=cvr_file, key=enc_key)
                        else:
                            st.error("Please fill all fields.")
                    elif option == "Encode Text in Image (1-Bit LSB)":
                        if cvr_file and sec_file and out_file:
                            ImageSteganography.encode_text(image_path=cvr_file, secret_text=sec_file, output_path=out_file)
                        else:
                            st.error("Please fill all fields.")
                    elif option == "Decode Text from Image (1-Bit LSB)":
                        if cvr_file:
                            ImageSteganography.decode_text(image_path=cvr_file)
                        else:
                            st.error("Please fill all fields.")
                    elif option == "Encode Image in Image (4-Bit LSB/MSB)":
                        if cvr_file and sec_file and out_file:
                            ImageSteganography.encode_image(cover_path=cvr_file, secret_path=sec_file, output_path=out_file)
                        else:
                            st.error("Please fill all fields.")
                    elif option == "Decode Image from Image (4-Bit LSB/MSB)":
                        if cvr_file and out_file:
                            ImageSteganography.decode_image(stego_path=cvr_file, output_path=out_file)
                        else:
                            st.error("Please fill all fields.")
                except Exception as e:
                    st.error(f"Error: {e}")
            
            output = out.getvalue()
            if output:
                render_terminal_output(output)
            else:
                st.success("Operation Finished (Check directory for output files).")
    else:
        st.error("Backend modules not available.")

def screen_forensics(option):
    render_page_header("Digital Forensics", option or "Digital Forensics")
    st.markdown("---")
    
    if option in ["Full File Analysis (Hashes, Signature, Entropy)", "Extract Strings from Binary"]:
        filepath = st.text_input("Enter path to target file:")
        if st.button("Analyze"):
            if not filepath:
                st.error("File path required.")
            else:
                with st.spinner("Analyzing..."):
                    with capture_stdout() as out:
                        try:
                            if BACKEND_AVAILABLE:
                                if "Analysis" in option:
                                    InvestigationTool.analyze_file(filepath)
                                else:
                                    InvestigationTool.extract_strings(filepath)
                        except Exception as e:
                            st.error(f"Error: {e}")
                    render_terminal_output(out.getvalue())
                    
    elif option == "Recursive Directory & File Scanner":
        task_id = "directory_scanner"
        if not render_running_task(task_id, "### Directory Scanner Background Execution"):
            root = st.text_input("Enter root directory path to scan:")
            if st.button("Scan Directory"):
                if not root:
                    st.error("Directory path required.")
                else:
                    cmd = [sys.executable, "runner.py", "DirectoryScanner", json.dumps({"root": root})]
                    start_task(task_id, cmd)
                    st.rerun()

def screen_osint(option):
    render_page_header("OSINT", option or "OSINT")
    st.markdown("---")
    
    if option == "SQL Injector":
        task_id = "sql_injector"
        if not render_running_task(task_id, "### SQLMap Background Execution"):
            url = st.text_input("Enter target URL for SQL testing:")
            if st.button("Run SQLMap"):
                if not url:
                    st.error("Target URL required.")
                else:
                    cmd = [sys.executable, "modules/sqlmap-master/sqlmap.py", "-u", url, "--batch", "--threads=5"]
                    start_task(task_id, cmd, cwd=os.path.dirname(os.path.abspath(__file__)))
                    st.rerun()
                        
    elif option == "Port Scanner":
        task_id = "port_scanner"
        if not render_running_task(task_id, "### Port Scanner Background Execution"):
            target = st.text_input("Enter target IP address or domain:")
            ports = st.selectbox("Select ports for Phase 1 socket scan:", ["common", "all", "custom"])
            if ports == "custom":
                ports = st.text_input("Enter space-separated custom list:")
                
            only_open = st.checkbox("Show only open ports in Phase 1?")
            
            if st.button("Start Port Scan"):
                if not target:
                    st.error("Target required.")
                else:
                    port_list = []
                    if ports == "all": port_list = list(range(1, 65536))
                    elif ports == "common": port_list = [80, 443, 21, 22, 23, 25, 53, 110, 111, 135, 139, 143, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
                    else: port_list = [int(p) for p in ports.split()]
                        
                    cmd = [sys.executable, "runner.py", "OptimizedPortScanner", json.dumps({
                        "target": target, "ports": ports, "port_list": port_list, "only_open": only_open
                    })]
                    start_task(task_id, cmd)
                    st.rerun()
                        
    elif option == "Username Hunter":
        task_id = "username_hunter"
        if not render_running_task(task_id, "### Username Hunter Background Execution"):
            username = st.text_input("Enter target username to hunt:")
            if st.button("Hunt Username"):
                if not username:
                    st.error("Username required.")
                else:
                    cmd = [sys.executable, "runner.py", "UsernameHunter", json.dumps({"username": username})]
                    start_task(task_id, cmd)
                    st.rerun()

def screen_crypto(option):
    render_page_header("Cryptographic Engine", option or "Cryptographic Engine")
    st.markdown("---")
    
    algo = option
    input_mode = st.radio("Payload Vector", ["Text Input", "File Upload"], horizontal=True)
    data_to_process = None
    if input_mode == "Text Input":
        t = st.text_area("Payload Data:")
        if t: data_to_process = t.encode('utf-8')
    else:
        f = st.file_uploader("Upload Payload:")
        if f is not None: data_to_process = f.read()

    if algo == "SHA-256":
        if st.button("Generate Hash"):
            if data_to_process:
                st.session_state.hash_output = engine.generate_sha256(data_to_process)
                st.success("Hash generated.")
                st.code(st.session_state.hash_output, language="text")
            else:
                st.error("Payload required.")
                
    elif algo == "AES-128":
        if st.button("Generate AES Key"):
            st.session_state.aes_key = engine.generate_aes_key()
            st.success("AES Key Generated.")
        
        current_key = st.text_input("Provided AES Key (Overrides session key):", type="password")
        current_key = current_key.encode('utf-8') if current_key else st.session_state.aes_key
        
        if current_key and not st.text_input("Provided AES Key (Overrides session key):", type="password", key="aes_k"):
             st.code(current_key.decode('utf-8'), language='text')
             
        action = st.radio("Action", ["Encrypt", "Decrypt"], horizontal=True)
        if st.button(f"Execute AES {action}"):
            if not data_to_process or not current_key:
                st.error("Payload and Key required.")
            else:
                try:
                    if action == "Encrypt":
                        res = engine.aes_encrypt(data_to_process, current_key)
                        st.session_state.encrypted_output = base64.b64encode(res).decode('utf-8')
                        st.success("Encrypted successfully.")
                        st.code(st.session_state.encrypted_output, language="text")
                    else:
                        raw = base64.b64decode(data_to_process) if isinstance(data_to_process, str) else base64.b64decode(data_to_process.decode('utf-8'))
                        res = engine.aes_decrypt(raw, current_key)
                        st.session_state.decrypted_output = res.decode('utf-8', errors='replace')
                        st.success("Decrypted successfully.")
                        st.code(st.session_state.decrypted_output, language="text")
                except Exception as e:
                    st.error(f"AES Error: {e}")

    elif algo == "RSA-2048":
        if st.button("Generate RSA Keypair"):
            with st.spinner("Generating..."):
                st.session_state.rsa_private, st.session_state.rsa_public = engine.generate_rsa_keypair()
                st.success("RSA Keypair Generated.")
                
        action = st.radio("Action", ["Encrypt", "Decrypt"], horizontal=True)
        
        if action == "Encrypt":
            pub = st.text_area("Public Key (PEM):")
            pub = pub.encode('utf-8') if pub else st.session_state.rsa_public
            if pub and not st.text_area("Public Key (PEM):", key="rsa_p"):
                st.code(pub.decode('utf-8'), language="text")
                
            if st.button("Execute RSA Encrypt"):
                if not data_to_process or not pub:
                    st.error("Payload and Public Key required.")
                else:
                    try:
                        with st.status("Encrypting..."):
                            res = engine.rsa_encrypt(data_to_process, pub)
                            st.session_state.encrypted_output = base64.b64encode(res).decode('utf-8')
                        st.code(st.session_state.encrypted_output, language="text")
                    except Exception as e:
                        st.error(f"RSA Error: {e}")
        else:
            priv = st.text_area("Private Key (PEM):", type="password")
            priv = priv.encode('utf-8') if priv else st.session_state.rsa_private
            
            if st.button("Execute RSA Decrypt"):
                if not data_to_process or not priv:
                    st.error("Payload and Private Key required.")
                else:
                    try:
                        with st.status("Decrypting..."):
                            raw = base64.b64decode(data_to_process) if isinstance(data_to_process, str) else base64.b64decode(data_to_process.decode('utf-8'))
                            res = engine.rsa_decrypt(raw, priv)
                            st.session_state.decrypted_output = res.decode('utf-8', errors='replace')
                        st.code(st.session_state.decrypted_output, language="text")
                    except Exception as e:
                        st.error(f"RSA Error: {e}")

# --- MAIN LOGIC ---
def main():
    inject_custom_css()
    render_custom_header()
    
    # ── Sidebar Logo & Title ───────────────────────────────────────────────
    st.sidebar.markdown("""
        <div style="
            text-align:center;
            padding: 20px 10px 10px 10px;
            border-bottom: 1px solid #1c2333;
            margin-bottom: 8px;
        ">
            <div style="margin-bottom:6px;filter:drop-shadow(0 0 10px #00f2ff);">
                <svg width="54" height="54" viewBox="0 0 54 54" fill="none" xmlns="http://www.w3.org/2000/svg">
                  <!-- Lock body with crack -->
                  <rect x="8" y="24" width="32" height="24" rx="3" fill="#0a0a0c" stroke="#00f2ff" stroke-width="1.8"/>
                  <!-- Crack lines on lock body -->
                  <polyline points="20,28 23,34 19,38 22,44" stroke="#00f2ff" stroke-width="1.4" stroke-linecap="round" opacity="0.7"/>
                  <!-- Shackle (open/broken - right side lifted) -->
                  <path d="M13 24 L13 16 Q13 8 24 8 Q35 8 35 16 L35 21" stroke="#00f2ff" stroke-width="2" fill="none" stroke-linecap="round"/>
                  <!-- Broken gap -->
                  <line x1="35" y1="21" x2="35" y2="24" stroke="#ff003c" stroke-width="2" stroke-dasharray="2,2"/>
                  <!-- Lockpick tool threading through -->
                  <line x1="36" y1="4" x2="22" y2="22" stroke="#fce205" stroke-width="1.6" stroke-linecap="round"/>
                  <!-- Pickpick tip diamond -->
                  <polygon points="22,22 20,25 22,28 24,25" fill="#fce205" opacity="0.9"/>
                  <!-- Pick handle end circle -->
                  <circle cx="38" cy="3" r="2.5" fill="#fce205" opacity="0.8"/>
                  <!-- Keyhole -->
                  <circle cx="24" cy="33" r="3" fill="#00f2ff" opacity="0.5"/>
                  <rect x="22.5" y="33" width="3" height="5" rx="1" fill="#00f2ff" opacity="0.5"/>
                </svg>
            </div>
            <div style="font-family:'Courier New',monospace;font-size:18px;font-weight:bold;
                color:#00f2ff;letter-spacing:3px;text-shadow:0 0 10px rgba(0,242,255,0.6);">CIPHERPICK</div>
            <div style="font-family:'Courier New',monospace;font-size:9px;color:#445566;
                letter-spacing:2px;margin-top:2px;">ADVANCED SECURITY TOOLKIT</div>
            <div style="margin-top:8px;font-family:'Courier New',monospace;font-size:11px;color:#00ff00;display:flex;align-items:center;justify-content:center;gap:6px;">
                <span style="display:inline-block;width:7px;height:7px;border-radius:50%;
                    background:#00ff00;box-shadow:0 0 6px #00ff00;animation:pulse 1.5s infinite;"></span>
                Security Status: Active
            </div>
        </div>
    """, unsafe_allow_html=True)

    # ── Top-level Navigation ──────────────────────────────────────────────
    nav_items = [
        ("1. Attacks"),
        ("2. StiganoMessenger"),
        ("3. Digital Forensics"),
        ("4. OSINT and Information Gathering"),
        ("5. Cryptographic Engine"),
    ]
    labels = [f"{label}" for label in nav_items]
    page = st.sidebar.radio("", labels, label_visibility="collapsed")

    st.sidebar.markdown('<div style="height:10px"></div>', unsafe_allow_html=True)

    # ── Sub-tool Selector in Sidebar ──────────────────────────────────────
    if "1. Attacks" in page:
        st.sidebar.markdown('<div style="font-size:10px;color:#445566;letter-spacing:2px;padding:6px 4px 2px 4px;">── TOOL ──────────────────</div>', unsafe_allow_html=True)
        option = st.sidebar.selectbox("Select attack:", [
            "PDF Password Recovery",
            "MITM (Man-In-The-Middle) Interception",
            "Zphisher (Automated Phishing Tool)",
            "Advanced Password Cracking"
        ], label_visibility="collapsed")
        st.sidebar.markdown(f'<div style="font-size:11px;color:#8b9bab;padding:2px 4px;">▸ {option}</div>', unsafe_allow_html=True)

    elif "2. StiganoMessenger" in page:
        st.sidebar.markdown('<div style="font-size:10px;color:#445566;letter-spacing:2px;padding:6px 4px 2px 4px;">── TOOL ──────────────────</div>', unsafe_allow_html=True)
        option = st.sidebar.selectbox("Select operation:", [
            "Encode Text in Text (Zero-Width XOR)",
            "Decode Text from Text (Zero-Width XOR)",
            "Encode Text in Image (1-Bit LSB)",
            "Decode Text from Image (1-Bit LSB)",
            "Encode Image in Image (4-Bit LSB/MSB)",
            "Decode Image from Image (4-Bit LSB/MSB)"
        ], label_visibility="collapsed")
        st.sidebar.markdown(f'<div style="font-size:11px;color:#8b9bab;padding:2px 4px;">▸ {option}</div>', unsafe_allow_html=True)

    elif "3. Digital Forensics" in page:
        st.sidebar.markdown('<div style="font-size:10px;color:#445566;letter-spacing:2px;padding:6px 4px 2px 4px;">── TOOL ──────────────────</div>', unsafe_allow_html=True)
        option = st.sidebar.selectbox("Select scan:", [
            "Full File Analysis (Hashes, Signature, Entropy)",
            "Extract Strings from Binary",
            "Recursive Directory & File Scanner"
        ], label_visibility="collapsed")
        st.sidebar.markdown(f'<div style="font-size:11px;color:#8b9bab;padding:2px 4px;">▸ {option}</div>', unsafe_allow_html=True)

    elif "4. OSINT" in page:
        st.sidebar.markdown('<div style="font-size:10px;color:#445566;letter-spacing:2px;padding:6px 4px 2px 4px;">── TOOL ──────────────────</div>', unsafe_allow_html=True)
        option = st.sidebar.selectbox("Select tool:", [
            "SQL Injector",
            "Port Scanner",
            "Username Hunter"
        ], label_visibility="collapsed")
        st.sidebar.markdown(f'<div style="font-size:11px;color:#8b9bab;padding:2px 4px;">▸ {option}</div>', unsafe_allow_html=True)

    elif "5. Cryptographic Engine" in page:
        st.sidebar.markdown('<div style="font-size:10px;color:#445566;letter-spacing:2px;padding:6px 4px 2px 4px;">── PROTOCOL ─────────────</div>', unsafe_allow_html=True)
        option = st.sidebar.selectbox("Select protocol:", [
            "AES-128", "RSA-2048", "SHA-256"
        ], label_visibility="collapsed")
        st.sidebar.markdown(f'<div style="font-size:11px;color:#8b9bab;padding:2px 4px;">▸ {option}</div>', unsafe_allow_html=True)

    else:
        option = None
    
    # ── Live Task Status Panel ──────────────────────────────────────────────
    tasks = st.session_state.get('tasks', {})
    running = {tid: t for tid, t in tasks.items() if t['process'].poll() is None}

    st.sidebar.markdown("""
        <div style="
            margin-top: 14px;
            padding: 10px 14px 4px 14px;
            border-top: 1px solid #1c2333;
        ">
            <div style="
                font-size: 10px;
                color: #445566;
                letter-spacing: 2px;
                text-transform: uppercase;
                margin-bottom: 6px;
            ">● Active Tasks</div>
        </div>
    """, unsafe_allow_html=True)

    TASK_LABELS = {
        'sql_injector':    ('🧨', 'SQL Injector'),
        'port_scanner':    ('📡', 'Port Scanner'),
        'username_hunter': ('👤', 'Username Hunter'),
        'pdf_recovery':    ('📄', 'PDF Recovery'),
        'directory_scanner': ('📂', 'Dir Scanner'),
    }
    if running:
        for tid in running:
            icon, label = TASK_LABELS.get(tid, ('⚙️', tid))
            st.sidebar.markdown(
                f'<div style="display:flex;align-items:center;gap:8px;padding:5px 14px;'
                f'background:rgba(0,242,255,0.04);border-radius:6px;margin:2px 6px;'
                f'border:1px solid rgba(0,242,255,0.15);">'
                f'<span style="font-size:14px">{icon}</span>'
                f'<span style="font-size:12px;color:#8b9bab;flex:1">{label}</span>'
                f'<span style="display:inline-block;width:7px;height:7px;border-radius:50%;'
                f'background:#00ff00;box-shadow:0 0 6px #00ff00;animation:pulse 1.5s infinite;"></span>'
                f'</div>',
                unsafe_allow_html=True
            )
    else:
        st.sidebar.markdown(
            '<div style="padding:4px 14px;font-size:12px;color:#445566;">No active tasks</div>',
            unsafe_allow_html=True
        )

    # ── Footer ──────────────────────────────────────────────────────────────
    st.sidebar.markdown("""
        <div style="
            position: fixed;
            bottom: 0;
            padding: 12px 14px;
            border-top: 1px solid #1c2333;
            font-size: 10px;
            color: #2a3444;
            letter-spacing: 1px;
            font-family: 'Courier New', monospace;
            width: 230px;
            background: #080c12;
        ">
            <div style="color:#445566;">v2.0 · CYBERPUNK-DARK</div>
            <div style="margin-top:2px;">
                <span style="color:#00ff00;">●</span> SYSTEM ONLINE
            </div>
        </div>
    """, unsafe_allow_html=True)

    # ── Route Pages ────────────────────────────────────────────────────────
    if "1. Attacks" in page:
        screen_attacks(option)
    elif "2. StiganoMessenger" in page:
        screen_stigano(option)
    elif "3. Digital Forensics" in page:
        screen_forensics(option)
    elif "4. OSINT" in page:
        screen_osint(option)
    elif "5. Cryptographic Engine" in page:
        screen_crypto(option)

if __name__ == "__main__":
    main()
