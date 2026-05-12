import os
import sys
import threading
try:
    import customtkinter as ctk
except ImportError:
    print("Please install customtkinter to run this GUI: pip install customtkinter")
    exit()

from tkinter import filedialog

# --- Backend Imports ---
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
try:
    from modules.scanner.port_scanner import PortScanner
    from modules.stegano.image_stegano import ImageSteganography
    from modules.password_cracker.numeric_attack import NumericAttack
    from modules.password_cracker.mask_attack import MaskAttack
    from modules.password_cracker.trie_dictionary_attack import TrieDictionaryAttack
    from modules.forensics.investigation_tool import InvestigationTool
except ImportError as e:
    print(f"Warning: Backend module missing. Some features may not work. {e}")


# --- Color Palette & Styling ---
BG_COLOR = "#000000"
FG_GREEN = "#00FF00"
HOVER_GREEN = "#00CC00"
DARK_GREY = "#111111"

FONT_MAIN = ("Consolas", 12)
FONT_HEADER = ("Consolas", 16, "bold")
FONT_ASCII = ("Consolas", 12, "bold")

import re

class RedirectText:
    def __init__(self, text_ctrl):
        self.output = text_ctrl
        self.output.tag_config("GREEN", foreground="#00FF00")
        self.output.tag_config("RED", foreground="#FF0000")
        self.output.tag_config("YELLOW", foreground="#FFFF00")
        self.output.tag_config("BLUE", foreground="#0088FF")
        self.output.tag_config("CYAN", foreground="#00FFFF")
        self.output.tag_config("MAGENTA", foreground="#FF00FF")
        self.output.tag_config("DEFAULT", foreground="#FFFFFF")
        self.ansi_pattern = re.compile(r'\033\[([0-9;]*?)m')
        self.current_tag = "DEFAULT"

    def write(self, string):
        parts = self.ansi_pattern.split(string)
        for i, part in enumerate(parts):
            if i % 2 == 1: # ANSI code
                codes = part.split(';')
                for code in codes:
                    if code in ('32', '92'):
                        self.current_tag = "GREEN"
                    elif code in ('31', '91'):
                        self.current_tag = "RED"
                    elif code in ('33', '93'):
                        self.current_tag = "YELLOW"
                    elif code in ('34', '94'):
                        self.current_tag = "BLUE"
                    elif code in ('36', '96'):
                        self.current_tag = "CYAN"
                    elif code in ('35', '95'):
                        self.current_tag = "MAGENTA"
                    elif code in ('0', '37', '39', ''):
                        self.current_tag = "DEFAULT"
            else: # Text part
                if part:
                    self.output.insert("end", part, tags=self.current_tag)
        self.output.see("end")

    def flush(self):
        pass

class CipherPickC2(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        # Window Configuration
        self.title("CipherPick Framework C2")
        self.geometry("1100x750")
        
        # Enforce dark mode and black background
        ctk.set_appearance_mode("dark")
        self.configure(fg_color=BG_COLOR)
        
        # Layout weights
        self.grid_rowconfigure(1, weight=1)      # Main workspace row
        self.grid_columnconfigure(1, weight=1)   # Main workspace col
        
        # UI Assembly
        self.create_header()
        self.create_sidebar()
        self.create_main_workspace()
        self.create_console()
        
        # Redirect stdout to console
        sys.stdout = RedirectText(self.console)
        
        # Dictionary to store swappable frames
        self.frames = {}
        self.setup_tool_frames()
        
        # Default view
        self.show_frame("Attacks")

    def create_bordered_frame(self, master, **kwargs):
        """Helper to create frames with 1px neon green borders."""
        return ctk.CTkFrame(
            master, 
            border_width=1, 
            border_color=FG_GREEN, 
            fg_color=BG_COLOR, 
            corner_radius=0, 
            **kwargs
        )

    def create_header(self):
        header_frame = self.create_bordered_frame(self)
        header_frame.grid(row=0, column=0, columnspan=2, sticky="ew", padx=5, pady=5)
        
        ascii_title = r"""
  ____ ___ ____  _   _ _____ ____  ____ ___ ____ _  __
 / ___|_ _|  _ \| | | | ____|  _ \|  _ \_ _/ ___| |/ /
| |    | || |_) | |_| |  _| | |_) | |_) | | |   | ' / 
| |___ | ||  __/|  _  | |___|  _ <|  __/| | |___| . \ 
 \____|___|_|   |_| |_|_____|_| \_\_|  |___\____|_|\_\
"""
        lbl = ctk.CTkLabel(header_frame, text=ascii_title, text_color=FG_GREEN, font=FONT_ASCII, justify="center")
        lbl.pack(pady=5)

    def create_sidebar(self):
        sidebar_frame = self.create_bordered_frame(self, width=220)
        sidebar_frame.grid(row=1, column=0, sticky="ns", padx=5, pady=(0, 5))
        sidebar_frame.grid_propagate(False)
        
        buttons = ["Attacks", "Steganography", "Forensics", "Port Scanner", "SQL Injector"]
        
        for btn_text in buttons:
            btn = ctk.CTkButton(
                sidebar_frame, 
                text=btn_text, 
                font=FONT_MAIN,
                fg_color=DARK_GREY,
                text_color=FG_GREEN,
                border_width=1,
                border_color=FG_GREEN,
                hover_color=FG_GREEN,
                corner_radius=0,
                command=lambda t=btn_text: self.show_frame(t)
            )
            # Hover bindings to make text black when background turns solid green
            btn.bind("<Enter>", lambda e, b=btn: b.configure(text_color=BG_COLOR))
            btn.bind("<Leave>", lambda e, b=btn: b.configure(text_color=FG_GREEN))
            btn.pack(pady=10, padx=15, fill="x")

    def create_main_workspace(self):
        self.main_container = self.create_bordered_frame(self)
        self.main_container.grid(row=1, column=1, sticky="nsew", padx=(0, 5), pady=(0, 5))
        self.main_container.grid_rowconfigure(0, weight=1)
        self.main_container.grid_columnconfigure(0, weight=1)

    def create_console(self):
        console_frame = self.create_bordered_frame(self, height=160)
        console_frame.grid(row=2, column=0, columnspan=2, sticky="ew", padx=5, pady=(0, 5))
        console_frame.grid_propagate(False)
        
        lbl = ctk.CTkLabel(console_frame, text="LOGS & OUTPUT", text_color=FG_GREEN, font=FONT_HEADER)
        lbl.pack(anchor="w", padx=10, pady=(5, 0))
        
        self.console = ctk.CTkTextbox(
            console_frame, 
            fg_color=DARK_GREY, 
            text_color="#FFFFFF", 
            font=FONT_MAIN,
            border_width=0,
            corner_radius=0
        )
        self.console.pack(fill="both", expand=True, padx=5, pady=(0, 5))
        self.console.insert("end", "[*] CipherPick UI initialized successfully.\n")

    def log_msg(self, msg):
        print(msg)

    def show_frame(self, frame_name):
        """Frame-swapping mechanism"""
        for frame in self.frames.values():
            frame.grid_forget()
            
        target_frame = self.frames.get(frame_name)
        if target_frame:
            target_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)

    def setup_tool_frames(self):
        # ----------------------------------------------------------------------
        # 1. PORT SCANNER SCREEN
        # ----------------------------------------------------------------------
        f_port = self.create_bordered_frame(self.main_container)
        self.frames["Port Scanner"] = f_port
        
        ctk.CTkLabel(f_port, text="PORT SCANNER", text_color=FG_GREEN, font=FONT_HEADER).pack(pady=(15, 20))
        
        pr1 = ctk.CTkFrame(f_port, fg_color="transparent")
        pr1.pack(fill="x", padx=30, pady=5)
        ctk.CTkLabel(pr1, text="Target IP/Domain:", text_color=FG_GREEN, font=FONT_MAIN, width=150, anchor="w").pack(side="left")
        tgt_ip_entry = ctk.CTkEntry(pr1, fg_color=DARK_GREY, text_color=FG_GREEN, border_color=FG_GREEN, corner_radius=0)
        tgt_ip_entry.pack(side="left", fill="x", expand=True)

        pr2 = ctk.CTkFrame(f_port, fg_color="transparent")
        pr2.pack(fill="x", padx=30, pady=5)
        ctk.CTkLabel(pr2, text="Ports:", text_color=FG_GREEN, font=FONT_MAIN, width=120, anchor="w").pack(side="left")
        ports_entry = ctk.CTkComboBox(pr2, values=["common", "all"], fg_color=DARK_GREY, text_color=FG_GREEN, border_color=FG_GREEN, button_color=DARK_GREY, button_hover_color=FG_GREEN, dropdown_fg_color=DARK_GREY, dropdown_text_color=FG_GREEN, corner_radius=0)
        ports_entry.pack(side="left", fill="x", expand=True)
        ports_entry.set("common")
        
        pr2_desc = ctk.CTkFrame(f_port, fg_color="transparent")
        pr2_desc.pack(fill="x", padx=30, pady=(0, 10))
        ctk.CTkLabel(pr2_desc, text="Enter 'all', 'common', or space-separated ports (e.g. 80 443 22)", text_color="#00AA00", font=("Consolas", 10)).pack(side="left", padx=(120, 0))

        pr3 = ctk.CTkFrame(f_port, fg_color="transparent")
        pr3.pack(fill="x", padx=30, pady=5)
        only_open_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(pr3, text="Only show open ports", variable=only_open_var, text_color=FG_GREEN, fg_color=FG_GREEN, border_color=FG_GREEN, hover_color=HOVER_GREEN, corner_radius=0).pack(side="left", padx=(120, 0))

        def execute_port_scan():
            target = tgt_ip_entry.get()
            ports_input = ports_entry.get().strip().lower()
            if not target:
                self.log_msg("[!] Target IP/Domain required.")
                return
            
            port_list = []
            if ports_input == 'all':
                port_list = list(range(1, 65536))
            elif ports_input == 'common':
                port_list = [80, 443, 21, 22, 23, 25, 53, 110, 111, 135, 139, 143, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
            else:
                try:
                    port_list = [int(p) for p in ports_input.split()]
                except ValueError:
                    self.log_msg("[!] Invalid port list format.")
                    return
            
            def scan_thread():
                import shutil, subprocess
                if shutil.which('nmap') is None:
                    self.log_msg("[!] Nmap is not installed or not found in PATH.")
                    return
                cmd = ['nmap', '-A', '-vv', target]
                self.log_msg(f"[+] Running: {' '.join(cmd)}")
                try:
                    proc = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        bufsize=1,
                    )
                    for line in iter(proc.stdout.readline, ''):
                        self.log_msg(line.rstrip('\n'))
                    proc.stdout.close()
                    proc.wait()
                    self.log_msg("[+] Scan complete.")
                except Exception as e:
                    self.log_msg(f"[!] Scan Error: {e}")
            threading.Thread(target=scan_thread, daemon=True).start()

        btn_port = ctk.CTkButton(f_port, text="Start Scan", font=FONT_MAIN, fg_color=FG_GREEN, text_color=BG_COLOR, hover_color=HOVER_GREEN, corner_radius=0, command=execute_port_scan)
        btn_port.pack(pady=20)

        # ----------------------------------------------------------------------
        # 2. ATTACKS SCREEN
        # ----------------------------------------------------------------------
        f_atk = self.create_bordered_frame(self.main_container)
        self.frames["Attacks"] = f_atk
        
        ctk.CTkLabel(f_atk, text="OFFENSIVE ATTACKS & CRACKING", text_color=FG_GREEN, font=FONT_HEADER).pack(pady=(15, 20))
        
        ar1 = ctk.CTkFrame(f_atk, fg_color="transparent")
        ar1.pack(fill="x", padx=30, pady=10)
        ctk.CTkLabel(ar1, text="Target PDF/Hash:", text_color=FG_GREEN, font=FONT_MAIN, width=150, anchor="w").pack(side="left")
        tgt_entry = ctk.CTkEntry(ar1, fg_color=DARK_GREY, text_color=FG_GREEN, border_color=FG_GREEN, corner_radius=0)
        tgt_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        
        def browse_atk():
            path = filedialog.askopenfilename()
            if path:
                tgt_entry.delete(0, "end")
                tgt_entry.insert(0, path)
                
        ctk.CTkButton(ar1, text="Browse", width=80, fg_color=DARK_GREY, text_color=FG_GREEN, border_color=FG_GREEN, border_width=1, corner_radius=0, hover_color=FG_GREEN, command=browse_atk).pack(side="left")

        ar2 = ctk.CTkFrame(f_atk, fg_color="transparent")
        ar2.pack(fill="x", padx=30, pady=10)
        ctk.CTkLabel(ar2, text="Attack Type:", text_color=FG_GREEN, font=FONT_MAIN, width=150, anchor="w").pack(side="left")
        atk_cb = ctk.CTkComboBox(ar2, values=["Numeric", "Mask", "Dictionary"], fg_color=DARK_GREY, text_color=FG_GREEN, border_color=FG_GREEN, button_color=DARK_GREY, button_hover_color=FG_GREEN, dropdown_fg_color=DARK_GREY, dropdown_text_color=FG_GREEN, corner_radius=0)
        atk_cb.pack(side="left", fill="x", expand=True)

        def execute_attack():
            tgt = tgt_entry.get()
            atk_type = atk_cb.get()
            if not tgt:
                self.log_msg("[!] Target file required.")
                return
            def attack_thread():
                self.log_msg(f"[*] Launching {atk_type} Attack on {tgt}...\n")
                try:
                    if atk_type == "Numeric":
                        NumericAttack(tgt, 4).execute()
                    elif atk_type == "Mask":
                        MaskAttack(tgt, "?d?d?d?d").execute()
                    elif atk_type == "Dictionary":
                        TrieDictionaryAttack(tgt, "passwords.txt").execute()
                except Exception as e:
                    self.log_msg(f"[!] Attack Failed: {e}")
            threading.Thread(target=attack_thread, daemon=True).start()

        btn_atk = ctk.CTkButton(f_atk, text="Launch Attack", font=FONT_MAIN, fg_color=FG_GREEN, text_color=BG_COLOR, hover_color=HOVER_GREEN, corner_radius=0, command=execute_attack)
        btn_atk.pack(pady=30)

        # ----------------------------------------------------------------------
        # 3. STEGANOGRAPHY SCREEN
        # ----------------------------------------------------------------------
        f_steg = self.create_bordered_frame(self.main_container)
        self.frames["Steganography"] = f_steg
        
        ctk.CTkLabel(f_steg, text="STEGANOGRAPHY WORKSTATION", text_color=FG_GREEN, font=FONT_HEADER).pack(pady=(15, 20))
        
        def make_browse_row(parent, label_text):
            row = ctk.CTkFrame(parent, fg_color="transparent")
            row.pack(fill="x", padx=30, pady=10)
            ctk.CTkLabel(row, text=label_text, text_color=FG_GREEN, font=FONT_MAIN, width=120, anchor="w").pack(side="left")
            entry = ctk.CTkEntry(row, fg_color=DARK_GREY, text_color=FG_GREEN, border_color=FG_GREEN, corner_radius=0)
            entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
            ctk.CTkButton(row, text="Browse", width=80, fg_color=DARK_GREY, text_color=FG_GREEN, border_color=FG_GREEN, border_width=1, corner_radius=0, hover_color=FG_GREEN, command=lambda: [entry.delete(0, "end"), entry.insert(0, filedialog.askopenfilename() or "")]).pack(side="left")
            return entry

        cvr_ent = make_browse_row(f_steg, "Cover File:")
        sec_ent = make_browse_row(f_steg, "Secret File:")

        sr3 = ctk.CTkFrame(f_steg, fg_color="transparent")
        sr3.pack(fill="x", padx=30, pady=10)
        ctk.CTkLabel(sr3, text="XOR Key:", text_color=FG_GREEN, font=FONT_MAIN, width=120, anchor="w").pack(side="left")
        ctk.CTkEntry(sr3, fg_color=DARK_GREY, text_color=FG_GREEN, border_color=FG_GREEN, corner_radius=0).pack(side="left", fill="x", expand=True, padx=(0, 90))

        def execute_steg_encode():
            cvr = cvr_ent.get()
            sec = sec_ent.get()
            out = "stego_output.png"
            if not cvr or not sec:
                self.log_msg("[!] Cover and Secret files required for encoding.")
                return
            threading.Thread(target=lambda: ImageSteganography.encode_image(cvr, sec, out), daemon=True).start()

        def execute_steg_decode():
            stg = cvr_ent.get()
            out = "extracted_secret.png"
            if not stg:
                self.log_msg("[!] Stego File required in Cover File slot for decoding.")
                return
            threading.Thread(target=lambda: ImageSteganography.decode_image(stg, out), daemon=True).start()

        steg_btns = ctk.CTkFrame(f_steg, fg_color="transparent")
        steg_btns.pack(pady=30)
        
        ctk.CTkButton(steg_btns, text="Encode", font=FONT_MAIN, fg_color=FG_GREEN, text_color=BG_COLOR, hover_color=HOVER_GREEN, corner_radius=0, command=execute_steg_encode).pack(side="left", padx=15)
        btn_dec = ctk.CTkButton(steg_btns, text="Decode", font=FONT_MAIN, fg_color=DARK_GREY, text_color=FG_GREEN, border_color=FG_GREEN, border_width=1, hover_color=FG_GREEN, corner_radius=0, command=execute_steg_decode)
        btn_dec.bind("<Enter>", lambda e, b=btn_dec: b.configure(text_color=BG_COLOR))
        btn_dec.bind("<Leave>", lambda e, b=btn_dec: b.configure(text_color=FG_GREEN))
        btn_dec.pack(side="left", padx=15)

        # ----------------------------------------------------------------------
        # 4. FORENSICS SCREEN
        # ----------------------------------------------------------------------
        f_for = self.create_bordered_frame(self.main_container)
        self.frames["Forensics"] = f_for
        
        ctk.CTkLabel(f_for, text="DIGITAL FORENSICS TOOLKIT", text_color=FG_GREEN, font=FONT_HEADER).pack(pady=(15, 5))
        
        # File Analysis Row
        for1 = ctk.CTkFrame(f_for, fg_color="transparent")
        for1.pack(fill="x", padx=30, pady=10)
        ctk.CTkLabel(for1, text="Target File:", text_color=FG_GREEN, font=FONT_MAIN, width=120, anchor="w").pack(side="left")
        for_entry = ctk.CTkEntry(for1, fg_color=DARK_GREY, text_color=FG_GREEN, border_color=FG_GREEN, corner_radius=0)
        for_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        ctk.CTkButton(for1, text="Browse", width=80, fg_color=DARK_GREY, text_color=FG_GREEN, border_color=FG_GREEN, border_width=1, corner_radius=0, hover_color=FG_GREEN, command=lambda: [for_entry.delete(0, "end"), for_entry.insert(0, filedialog.askopenfilename() or "")]).pack(side="left")

        def execute_forensics():
            filepath = for_entry.get()
            orig = orig_txt.get("1.0", "end-1c").strip()
            susp = susp_txt.get("1.0", "end-1c").strip()
            
            def for_thread():
                if filepath:
                    InvestigationTool.analyze_file(filepath)
                    InvestigationTool.extract_strings(filepath)
                if orig and susp:
                    self.log_msg("\n[*] Comparing Texts...")
                    if orig == susp:
                        self.log_msg("[+] Texts match perfectly.")
                    else:
                        self.log_msg("[-] Texts DO NOT MATCH. Possible tampering detected.")
            threading.Thread(target=for_thread, daemon=True).start()

        ctk.CTkButton(f_for, text="Analyze File & Text", font=FONT_MAIN, fg_color=FG_GREEN, text_color=BG_COLOR, hover_color=HOVER_GREEN, corner_radius=0, command=execute_forensics).pack(pady=15)

        # Text Analysis Row
        txt_frame = ctk.CTkFrame(f_for, fg_color="transparent")
        txt_frame.pack(fill="both", expand=True, padx=20, pady=5)
        txt_frame.grid_columnconfigure(0, weight=1)
        txt_frame.grid_columnconfigure(1, weight=1)
        txt_frame.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(txt_frame, text="Original Text", text_color=FG_GREEN, font=FONT_MAIN).grid(row=0, column=0, pady=5)
        ctk.CTkLabel(txt_frame, text="Suspected Text", text_color=FG_GREEN, font=FONT_MAIN).grid(row=0, column=1, pady=5)

        orig_txt = ctk.CTkTextbox(txt_frame, fg_color=DARK_GREY, text_color=FG_GREEN, border_color=FG_GREEN, border_width=1, corner_radius=0)
        orig_txt.grid(row=1, column=0, sticky="nsew", padx=10, pady=5)
        susp_txt = ctk.CTkTextbox(txt_frame, fg_color=DARK_GREY, text_color=FG_GREEN, border_color=FG_GREEN, border_width=1, corner_radius=0)
        susp_txt.grid(row=1, column=1, sticky="nsew", padx=10, pady=5)

        # ----------------------------------------------------------------------
        # 5. SQL INJECTOR SCREEN
        # ----------------------------------------------------------------------
        f_sql = self.create_bordered_frame(self.main_container)
        self.frames["SQL Injector"] = f_sql
        
        ctk.CTkLabel(f_sql, text="SQL INJECTOR (SQLMAP)", text_color=FG_GREEN, font=FONT_HEADER).pack(pady=(15, 20))
        
        sql1 = ctk.CTkFrame(f_sql, fg_color="transparent")
        sql1.pack(fill="x", padx=30, pady=10)
        ctk.CTkLabel(sql1, text="Target URL:", text_color=FG_GREEN, font=FONT_MAIN, width=120, anchor="w").pack(side="left")
        sql_tgt_entry = ctk.CTkEntry(sql1, fg_color=DARK_GREY, text_color=FG_GREEN, border_color=FG_GREEN, corner_radius=0)
        sql_tgt_entry.pack(side="left", fill="x", expand=True)

        def execute_sql_injector():
            url = sql_tgt_entry.get().strip()
            if not url:
                self.log_msg("[!] Target URL required.")
                return
            
            def sql_thread():
                self.log_msg(f"[*] Starting SQLMap on {url}...\n")
                try:
                    import subprocess
                    process = subprocess.Popen([sys.executable, "modules/sqlmap-master/sqlmap.py", "-u", url, "--batch"],
                                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, cwd=os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
                    for line in iter(process.stdout.readline, ''):
                        if line:
                            self.log_msg(line.rstrip('\\n'))
                    process.stdout.close()
                    process.wait()
                    self.log_msg("[+] SQLMap execution finished.")
                except Exception as e:
                    self.log_msg(f"[!] SQLMap Error: {e}")
                    
            threading.Thread(target=sql_thread, daemon=True).start()

        ctk.CTkButton(f_sql, text="Run SQLMap", font=FONT_MAIN, fg_color=FG_GREEN, text_color=BG_COLOR, hover_color=HOVER_GREEN, corner_radius=0, command=execute_sql_injector).pack(pady=20)

if __name__ == "__main__":
    app = CipherPickC2()
    app.mainloop()
