import json
import tkinter as tk
from tkinter import ttk, messagebox
from static_harbor_engine import load_settings, save_settings, load_ack, password_strength, generate_password, parse_ports, scan_ports

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("StaticHarbor")
        self.geometry("940x640")
        self.minsize(900, 580)
        self.s = load_settings()

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=10, pady=10)
        self.tab_pw = ttk.Frame(nb)
        self.tab_scan = ttk.Frame(nb)
        self.tab_settings = ttk.Frame(nb)
        nb.add(self.tab_pw, text="Passwords")
        nb.add(self.tab_scan, text="Port Scanner")
        nb.add(self.tab_settings, text="Settings")

        self._pw_tab()
        self._scan_tab()
        self._settings_tab()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _pw_tab(self):
        f = ttk.Frame(self.tab_pw, padding=10); f.pack(fill="both", expand=True)
        ttk.Label(f, text="Password Strength").grid(row=0, column=0, sticky="w")
        self.pw_entry = ttk.Entry(f, show="•", width=52); self.pw_entry.grid(row=1, column=0, sticky="w", pady=(6,6))
        ttk.Button(f, text="Check", command=self._pw_check).grid(row=1, column=1, padx=8)
        self.pw_out = tk.Text(f, height=10, wrap="word"); self.pw_out.grid(row=2, column=0, columnspan=2, sticky="nsew")
        self.pw_out.configure(state="disabled")

        ttk.Separator(f).grid(row=3, column=0, columnspan=2, sticky="ew", pady=10)
        ttk.Label(f, text="Password Generator").grid(row=4, column=0, sticky="w")

        row = ttk.Frame(f); row.grid(row=5, column=0, columnspan=2, sticky="w", pady=6)
        self.len_var = tk.IntVar(value=self.s.generator_length)
        ttk.Label(row, text="Length:").pack(side="left")
        ttk.Spinbox(row, from_=8, to=128, width=6, textvariable=self.len_var).pack(side="left", padx=(6,12))

        self.upper = tk.BooleanVar(value=self.s.generator_use_upper)
        self.lower = tk.BooleanVar(value=self.s.generator_use_lower)
        self.digits = tk.BooleanVar(value=self.s.generator_use_digits)
        self.symbols = tk.BooleanVar(value=self.s.generator_use_symbols)
        ttk.Checkbutton(row, text="Upper", variable=self.upper).pack(side="left", padx=6)
        ttk.Checkbutton(row, text="Lower", variable=self.lower).pack(side="left", padx=6)
        ttk.Checkbutton(row, text="Digits", variable=self.digits).pack(side="left", padx=6)
        ttk.Checkbutton(row, text="Symbols", variable=self.symbols).pack(side="left", padx=6)

        ttk.Button(f, text="Generate", command=self._pw_gen).grid(row=6, column=0, sticky="w", pady=6)
        self.gen_out = ttk.Entry(f, width=76); self.gen_out.grid(row=6, column=0, sticky="e", pady=6)

        f.columnconfigure(0, weight=1)
        f.rowconfigure(2, weight=1)

    def _pw_check(self):
        r = password_strength(self.pw_entry.get())
        self.pw_out.configure(state="normal")
        self.pw_out.delete("1.0","end")
        self.pw_out.insert("1.0", json.dumps(r, indent=2))
        self.pw_out.configure(state="disabled")

    def _pw_gen(self):
        try:
            pw = generate_password(int(self.len_var.get()), bool(self.upper.get()), bool(self.lower.get()),
                                   bool(self.digits.get()), bool(self.symbols.get()))
        except Exception as e:
            messagebox.showerror("Generator error", str(e)); return
        self.gen_out.delete(0,"end"); self.gen_out.insert(0,pw)

    def _scan_tab(self):
        f = ttk.Frame(self.tab_scan, padding=10); f.pack(fill="both", expand=True)
        top = ttk.Frame(f); top.pack(fill="x")
        self.host = tk.StringVar(value=self.s.last_host)
        self.ports = tk.StringVar(value=self.s.last_ports)
        self.timeout = tk.IntVar(value=self.s.scan_timeout_ms)
        self.threads = tk.IntVar(value=self.s.scan_threads)

        ttk.Label(top, text="Host:").pack(side="left")
        ttk.Entry(top, textvariable=self.host, width=24).pack(side="left", padx=(6,12))
        ttk.Label(top, text="Ports:").pack(side="left")
        ttk.Entry(top, textvariable=self.ports, width=34).pack(side="left", padx=(6,12))
        ttk.Label(top, text="Timeout(ms):").pack(side="left")
        ttk.Spinbox(top, from_=50, to=5000, increment=50, width=7, textvariable=self.timeout).pack(side="left", padx=(6,12))
        ttk.Label(top, text="Threads:").pack(side="left")
        ttk.Spinbox(top, from_=1, to=512, increment=1, width=6, textvariable=self.threads).pack(side="left", padx=(6,12))

        ttk.Button(top, text="Refresh ethics", command=self._refresh_ethics).pack(side="left", padx=(0,8))
        ttk.Button(top, text="Scan", command=self._scan).pack(side="left")

        self.scan_out = tk.Text(f, height=28, wrap="word"); self.scan_out.pack(fill="both", expand=True, pady=(10,0))
        self.scan_out.configure(state="disabled")
        ttk.Label(f, text="Scanning requires ethics ack via CLI: python static_harbor_engine.py ethics",
                  foreground="#d18f00").pack(anchor="w", pady=(8,0))

    def _refresh_ethics(self):
        ok = bool(load_ack().get("ok", False))
        messagebox.showinfo("Ethics status", "ACK OK" if ok else "ACK MISSING (run ethics command)")

    def _scan(self):
        if not bool(load_ack().get("ok", False)):
            messagebox.showerror("Ethics required", "Run: python static_harbor_engine.py ethics")
            return
        host = self.host.get().strip()
        ports_spec = self.ports.get().strip()
        ports = parse_ports(ports_spec)
        if not ports:
            messagebox.showerror("Ports error", "No valid ports."); return

        out = scan_ports(host, ports, int(self.timeout.get()), int(self.threads.get()))
        self.scan_out.configure(state="normal")
        self.scan_out.delete("1.0","end")
        self.scan_out.insert("1.0", json.dumps(out, indent=2))
        self.scan_out.configure(state="disabled")

        s = load_settings()
        s.last_host=host; s.last_ports=ports_spec
        s.scan_timeout_ms=int(self.timeout.get()); s.scan_threads=int(self.threads.get())
        save_settings(s)

    def _settings_tab(self):
        f = ttk.Frame(self.tab_settings, padding=10); f.pack(fill="both", expand=True)
        ttk.Label(f, text="Settings stored at ~/.static_harbor/settings.json").pack(anchor="w")
        self.settings_view = tk.Text(f, height=28, wrap="word"); self.settings_view.pack(fill="both", expand=True, pady=(10,0))
        self.settings_view.configure(state="disabled")
        ttk.Button(f, text="Refresh", command=self._refresh_settings).pack(anchor="w", pady=(8,0))
        self._refresh_settings()

    def _refresh_settings(self):
        s = load_settings()
        self.settings_view.configure(state="normal")
        self.settings_view.delete("1.0","end")
        self.settings_view.insert("1.0", json.dumps(s.__dict__, indent=2))
        self.settings_view.configure(state="disabled")

    def _on_close(self):
        s = load_settings()
        s.generator_length=int(self.len_var.get())
        s.generator_use_upper=bool(self.upper.get())
        s.generator_use_lower=bool(self.lower.get())
        s.generator_use_digits=bool(self.digits.get())
        s.generator_use_symbols=bool(self.symbols.get())
        save_settings(s)
        self.destroy()

def run_gui():
    App().mainloop()
