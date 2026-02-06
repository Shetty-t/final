import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import time
import os
import psutil
from scanner_engine import ScannerEngine
from system_scanner import SystemScanner

# --- THEME CONFIG ---
THEME = {
    "bg": "#0d1117",       # Dark Github/Hacker Black
    "fg": "#00ff00",       # Neon Green
    "accent": "#003300",   # Darker Green
    "warn": "#ff0000",     # Bright Red
    "font": ("Consolas", 10),
    "header_font": ("Consolas", 16, "bold"),
    "btn_bg": "#21262d",
    "btn_fg": "#58a6ff"    # Cyan/Blueish for buttons
}

class AntivirusApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SYSTEM_SECURITY_TERMINAL_V9")
        self.root.geometry("1100x750")
        self.root.configure(bg=THEME["bg"])

        self.engine = ScannerEngine()
        self.sys_scanner = SystemScanner()
        self.monitoring = False
        self.scan_thread = None

        self._apply_styles()
        self._setup_ui()
        self.toggle_monitor() 

    def _apply_styles(self):
        style = ttk.Style()
        style.theme_use("clam") # Better for custom colors
        
        # Treeview (Table) Dark Theme
        style.configure("Treeview", 
                        background="#161b22",
                        foreground=THEME["fg"],
                        fieldbackground="#161b22",
                        font=("Consolas", 9))
        style.configure("Treeview.Heading", 
                        background="#21262d", 
                        foreground="#ffffff", 
                        font=("Consolas", 10, "bold"))
        style.map("Treeview", background=[('selected', '#238636')])

    def _setup_ui(self):
        # --- Header ---
        header = tk.Frame(self.root, bg="#000000", bd=2, relief="sunken")
        header.pack(fill="x", padx=5, pady=5)
        
        tk.Label(header, text="[ SYSTEM_INTEGRITY_COMPROMISED? CHECKING... ]", 
                 font=THEME["header_font"], bg="#000000", fg=THEME["warn"]).pack(side="left", padx=10, pady=10)
        
        self.lbl_status = tk.Label(header, text="STATUS: PROTECTED", 
                                   font=("Consolas", 14, "bold"), bg="#000000", fg=THEME["fg"])
        self.lbl_status.pack(side="right", padx=10)

        # --- Tab System ---
        self.tabs = ttk.Notebook(self.root)
        self.tabs.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Style Tabs (Hack to make them look okay-ish in dark mode)
        # Tkinter tabs are hard to style perfectly dark without images, but we try.

        # Tab 1: COMMAND CENTER
        self.tab_home = tk.Frame(self.tabs, bg=THEME["bg"])
        self.tabs.add(self.tab_home, text=" > COMMAND_CENTER ")
        self._build_home_tab()

        # Tab 2: KERNEL_OPS
        self.tab_sys = tk.Frame(self.tabs, bg=THEME["bg"])
        self.tabs.add(self.tab_sys, text=" > KERNEL_OPS ")
        self._build_sys_tab()

        # Tab 3: NET_WARFARE
        self.tab_net = tk.Frame(self.tabs, bg=THEME["bg"])
        self.tabs.add(self.tab_net, text=" > NET_WARFARE ")
        self._build_net_tab()

    # ==========================
    # TAB 1: COMMAND CENTER
    # ==========================
    def _build_home_tab(self):
        # Layout: Left (Controls), Right (Live Terminal)
        paned = tk.PanedWindow(self.tab_home, orient="horizontal", bg=THEME["bg"], sashwidth=2)
        paned.pack(fill="both", expand=True, padx=5, pady=5)

        # Left Panel
        left = tk.Frame(paned, bg=THEME["bg"])
        paned.add(left, width=400)

        # Controls
        ctrl_frame = tk.LabelFrame(left, text="EXECUTE_SCAN", bg=THEME["bg"], fg="white", font=THEME["font"])
        ctrl_frame.pack(fill="x", pady=10)
        
        self._make_btn(ctrl_frame, ">> QUICK_SCAN", lambda: self.start_scan("quick")).pack(fill="x", pady=2)
        self._make_btn(ctrl_frame, ">> FULL_SYSTEM_SCAN", lambda: self.start_scan("full")).pack(fill="x", pady=2)
        self._make_btn(ctrl_frame, ">> ABORT_OPERATIONS", self.stop_scan, bg="#330000", fg="red").pack(fill="x", pady=5)
        self._make_btn(ctrl_frame, ">> SELECT_TARGET", self.custom_scan).pack(fill="x", pady=2)
        
        self.btn_monitor = self._make_btn(ctrl_frame, ">> STOP_SENTINEL", self.toggle_monitor, bg="#330000", fg="red")
        self.btn_monitor.pack(fill="x", pady=10)

        # THREAT LIST
        tk.Label(left, text="DETECTED_ANOMALIES:", bg=THEME["bg"], fg=THEME["warn"], font=("Consolas", 11, "bold")).pack(anchor="w", pady=(20, 5))
        
        cols = ("Path", "Threat_Level", "Conf", "Action")
        self.tree = ttk.Treeview(left, columns=cols, show="headings", height=15)
        for col in cols: 
            self.tree.heading(col, text=col.upper())
            self.tree.column(col, width=60 if col != "Path" else 180)
        self.tree.pack(fill="both", expand=True)
        
        # Threat Actions
        self._make_btn(left, ">> QUARANTINE_SELECTED", self.quarantine_selected, bg="#663300", fg="orange").pack(fill="x", pady=2)
        self._make_btn(left, ">> TERMINATE_FILE (DELETE)", self.delete_selected, bg="#660000", fg="red").pack(fill="x", pady=2)

        # Right Panel (Live Terminal)
        right = tk.Frame(paned, bg="black")
        paned.add(right)
        
        tk.Label(right, text="LIVE_SCAN_FEED:", bg="black", fg="#00ff00", font=("Consolas", 10)).pack(anchor="w")
        self.live_log = tk.Text(right, bg="black", fg="#00ff00", font=("Consolas", 9), insertbackground="white", state="disabled")
        self.live_log.pack(fill="both", expand=True)


    def _make_btn(self, parent, text, cmd, bg=THEME["btn_bg"], fg=THEME["btn_fg"]):
        return tk.Button(parent, text=text, command=cmd, bg=bg, fg=fg, activebackground=fg, activeforeground=bg, font=("Consolas", 10, "bold"), relief="flat", padx=10, pady=5)

    # ==========================
    # TAB 2: SYSTEM
    # ==========================
    def _build_sys_tab(self):
        frame = tk.Frame(self.tab_sys, bg=THEME["bg"])
        frame.pack(fill="both", expand=True, padx=20, pady=20)

        self._make_btn(frame, ">> SCAN_RAM_MEMORY (PROCESSES)", self.scan_ram, bg="#002244", fg="cyan").pack(fill="x", pady=5)
        self._make_btn(frame, ">> SCAN_EXTERNAL_MEDIA (USB)", self.scan_usb, bg="#002244", fg="cyan").pack(fill="x", pady=5)

        self.sys_log = tk.Text(frame, bg="black", fg="cyan", font=("Consolas", 9), insertbackground="white")
        self.sys_log.pack(fill="both", expand=True, pady=10)
        self.sys_log.insert("end", "> KERNEL_MODULE_LOADED...\n> WAITING_FOR_COMMAND...\n")
        
    # ==========================
    # TAB 3: NETWORK
    # ==========================
    def _build_net_tab(self):
        frame = tk.Frame(self.tab_net, bg=THEME["bg"])
        frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        self._make_btn(frame, ">> PING_SWEEP_LOCAL_NET", self.scan_network, bg="#220044", fg="magenta").pack(fill="x", pady=5)

        self.net_tree = ttk.Treeview(frame, columns=("IP", "HOST", "STATUS"), show="headings")
        for c in ("IP", "HOST", "STATUS"): self.net_tree.heading(c, text=c)
        self.net_tree.pack(fill="both", expand=True, pady=10)

    # --- LOGIC ---
    def log_terminal(self, msg):
        try:
            self.live_log.config(state="normal")
            self.live_log.insert("end", f"> {msg}\n")
            self.live_log.see("end")
            self.live_log.config(state="disabled")
        except: pass

    def custom_scan(self):
        path = filedialog.askdirectory()
        if path: self.start_scan("custom", path)

    def start_scan(self, mode, path=None):
        if self.scan_thread and self.scan_thread.is_alive():
            return
        
        self.scanning = True
        target = path if path else (os.path.expanduser("~") if mode == "quick" else "C:\\")
        self.scan_thread = threading.Thread(target=self._scan_worker, args=(target,), daemon=True)
        self.scan_thread.start()

    def stop_scan(self):
        self.scanning = False
        self.log_terminal("!!! ABORTING OPERATIONS !!!")
        self.lbl_status.config(text="STATUS: ABORTED", fg="red")

    def _scan_worker(self, target):
        self.lbl_status.config(text="STATUS: SCANNING...", fg="orange")
        self.log_terminal(f"INITIALIZING_SCAN: {target}")
        
        count = 0 
        for root, _, files in os.walk(target):
            if not self.scanning: break
            if "Windows" in root: continue
            
            for f in files:
                if not self.scanning: break
                p = os.path.join(root, f)
                
                # VISUAL FEEDBACK: Show what we are scanning
                if count % 5 == 0: 
                    self.log_terminal(f"SCANNING: {f[:30]}...")
                
                try:
                    status, conf, _ = self.engine.scan_file(p)
                    count += 1
                    
                    if status == "UNSAFE":
                        # --- THRESHOLD CHECK (Requested > 90%) ---
                        try:
                            score = float(conf.replace("%", ""))
                            if score < 90.0:
                                continue # Skip if risk is low (< 90)
                        except: pass # If parse fails, treat as high risk (safe fallback)
                        
                        self.tree.insert("", "0", values=(p, "CRITICAL", conf, "PENDING")) # Insert at top
                        self.log_terminal(f"!!! ANOMALY DETECTED (RISK {conf}): {f} !!!")
                except: pass
        
        if self.scanning:
            self.lbl_status.config(text="STATUS: PROTECTED", fg=THEME["fg"])
            self.log_terminal("SCAN_COMPLETE.")
        else:
            self.log_terminal("OPERATIONS_HALTED_BY_USER.")

    # --- KEEPING OTHER HANDLERS (USB/RAM) SIMILAR BUT WITH DARK THEME ---
    def log_sys(self, msg):
        self.sys_log.insert("end", f"> {msg}\n"); self.sys_log.see("end")

    def scan_ram(self):
        threading.Thread(target=self._ram_worker, daemon=True).start()
    def _ram_worker(self):
        self.log_sys("READING_PROCESS_MEMORY...")
        threats = self.sys_scanner.scan_memory(lambda m, c: self.log_sys(m) if c%10==0 else None)
        # Apply 90% filter to RAM too (manual filter here since system_scanner returns list)
        valid_threats = []
        if threats:
            for t in threats:
                try:
                    score = float(str(t['conf']).replace("%", ""))
                    if score >= 90.0: valid_threats.append(t)
                except: valid_threats.append(t)
        
        if valid_threats:
            for t in valid_threats: self.tree.insert("", "0", values=(f"MEM:{t['path']}", "HIGH", t['conf'], "KILL"))

    def scan_usb(self):
        threading.Thread(target=self._usb_worker, daemon=True).start()
    def _usb_worker(self):
        threats, msg = self.sys_scanner.scan_usb(lambda m, c: self.log_sys(m) if c%20==0 else None)
        self.log_sys(msg)
        # Apply 90% filter
        valid_threats = []
        if threats:
            for t in threats:
                try:
                    score = float(str(t['conf']).replace("%", ""))
                    if score >= 90.0: valid_threats.append(t)
                except: valid_threats.append(t)

        if valid_threats:
            for t in valid_threats: self.tree.insert("", "0", values=(t['path'], "HIGH", t['conf'], "QUARANTINE"))

    def scan_network(self):
        self.net_tree.delete(*self.net_tree.get_children())
        threading.Thread(target=self._net_worker, daemon=True).start()
    def _net_worker(self):
        devs = self.sys_scanner.scan_network_arp()
        for d in devs: self.net_tree.insert("", "end", values=(d['ip'], d['hostname'], d['status']))

    def toggle_monitor(self):
        if self.monitoring:
            self.monitoring = False
            self.btn_monitor.config(text=">> START_SENTINEL", fg="green")
        else:
            self.monitoring = True
            self.btn_monitor.config(text=">> STOP_SENTINEL", fg="red")
            threading.Thread(target=self._monitor_worker, daemon=True).start()

    def _monitor_worker(self):
        watch = [os.path.join(os.path.expanduser("~"), "Downloads")]
        seen = set()
        while self.monitoring:
            current = set()
            for d in watch:
                if os.path.exists(d):
                    for f in os.listdir(d): current.add(os.path.join(d, f))
            new = current - seen
            for f in new:
                self.log_terminal(f"NEW_FILE_INTERCEPTED: {f}")
                status, conf, _ = self.engine.scan_file(f)
                if status == "UNSAFE":
                    # --- THRESHOLD CHECK ---
                    try:
                        score = float(conf.replace("%", ""))
                        if score < 90.0: continue
                    except: pass
                    
                    self.tree.insert("", "0", values=(f, "CRITICAL", conf, "NEW_DROP"))
                    self.log_terminal(f"!!! BLOCKED (RISK {conf}): {f} !!!")
            seen = current
            time.sleep(2)

    def quarantine_selected(self):
        for i in self.tree.selection():
            p = self.tree.item(i, "values")[0]
            self.engine.quarantine_file(p)
            self.tree.set(i, "Action", "CONTAINED")
            
    def delete_selected(self):
        for i in self.tree.selection():
            p = self.tree.item(i, "values")[0]
            self.engine.delete_file(p)
            self.tree.delete(i)

if __name__ == "__main__":
    root = tk.Tk()
    app = AntivirusApp(root)
    root.mainloop()
