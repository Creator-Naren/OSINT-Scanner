"""Modern, dark-themed Tkinter GUI for the OSINT Scanner."""

import json
import os
import re
import subprocess
import sys
import threading
import webbrowser
from datetime import datetime

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

try:
    from modules import MODULES
    from modules._utils import sanitize_domain
    from output import OUTPUT_DIR, timestamp_now, write_json
except ImportError:
    from osint_scanner.modules import MODULES
    from osint_scanner.modules._utils import sanitize_domain
    from osint_scanner.output import OUTPUT_DIR, timestamp_now, write_json

# Color Palette (Cyber Dark Theme)
BG_DARK = "#0B0F19"
BG_CARD = "#141C2E"
BG_ENTRY = "#1E293B"
BORDER_COLOR = "#334155"
TEXT_PRIMARY = "#F8FAFC"
TEXT_MUTED = "#94A3B8"
ACCENT_CYAN = "#06B6D4"
ACCENT_CYAN_HOVER = "#0891B2"
ACCENT_BLUE = "#3B82F6"
COLOR_SUCCESS = "#10B981"
COLOR_WARNING = "#F59E0B"
COLOR_ERROR = "#EF4444"
FONT_FAMILY = "Segoe UI" if os.name == "nt" else "DejaVu Sans"
MONO_FONT = "Consolas" if os.name == "nt" else "Monospace"

TABS = [
    ("📊 Overview", "overview"),
    ("📋 WHOIS", "whois"),
    ("🌐 DNS", "dns"),
    ("📍 GeoIP", "geoip"),
    ("🔍 Shodan", "shodan"),
    ("🌿 Subdomains", "subdomains"),
    ("🔓 Leaks", "leaks"),
]

FIELDS = {
    "whois": [
        ("Registrar", "registrar"),
        ("Created", "creation_date"),
        ("Expires", "expiration_date"),
        ("Name Servers", "name_servers"),
        ("Contact Emails", "emails"),
    ],
    "dns": [
        ("A (IPv4)", "A"),
        ("AAAA (IPv6)", "AAAA"),
        ("MX (Mail)", "MX"),
        ("NS (Nameservers)", "NS"),
        ("TXT (Text)", "TXT"),
        ("CNAME (Alias)", "CNAME"),
        ("SOA (Authority)", "SOA"),
    ],
    "geoip": [
        ("IP Address", "ip"),
        ("City", "city"),
        ("Region", "region"),
        ("Country", "country"),
        ("ISP", "isp"),
        ("Organization", "org"),
        ("AS Number", "as"),
        ("Latitude", "lat"),
        ("Longitude", "lon"),
    ],
    "shodan": [
        ("Open Ports", "ports"),
        ("Hostnames", "hostnames"),
        ("Vulnerabilities", "vulns"),
        ("Operating System", "os"),
    ],
    "subdomains": [("Discovered Subdomains", "subdomains")],
    "leaks": [("GitHub Code Matches", "github_leaks"), ("Pwned Breach Count", "email_leaks")],
}


def _format_value(value) -> str:
    if isinstance(value, list):
        if not value:
            return "none"
        if isinstance(value[0], dict):
            lines = []
            for item in value:
                repo = item.get("repository", "unknown")
                path = item.get("path", "")
                url = item.get("html_url", "")
                lines.append(f"• {repo} ({path})\n  URL: {url}")
            return "\n".join(lines)
        return "\n".join(str(v) for v in value)
    return str(value)


class OSINTGui:
    def __init__(self, root):
        self.root = root
        root.title("OSINT Scanner — Cyber Threat & Recon Intelligence")
        root.geometry("1000 x 700")
        root.minsize(800, 520)
        root.configure(bg=BG_DARK)

        self._scanning = False
        self._results = {}
        self._json_path = None
        self._domain_list = []

        self._setup_styles()
        self._build_header()
        self._build_toolbar()
        self._build_tabs()
        self._build_statusbar()
        self._bind_shortcuts()

    def _setup_styles(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        # Global ttk styles
        style.configure(".", background=BG_DARK, foreground=TEXT_PRIMARY, font=(FONT_FAMILY, 10))
        style.configure("TFrame", background=BG_DARK)
        style.configure("Card.TFrame", background=BG_CARD, relief="flat")

        # Label styles
        style.configure("TLabel", background=BG_DARK, foreground=TEXT_PRIMARY, font=(FONT_FAMILY, 10))
        style.configure("Header.TLabel", background=BG_DARK, foreground=ACCENT_CYAN, font=(FONT_FAMILY, 16, "bold"))
        style.configure("SubHeader.TLabel", background=BG_DARK, foreground=TEXT_MUTED, font=(FONT_FAMILY, 9))
        style.configure("Status.TLabel", background=BG_CARD, foreground=TEXT_PRIMARY, font=(FONT_FAMILY, 9))

        # Button styles
        style.configure(
            "Primary.TButton",
            background=ACCENT_CYAN,
            foreground="#000000",
            font=(FONT_FAMILY, 10, "bold"),
            borderwidth=0,
            padding=(14, 6),
        )
        style.map("Primary.TButton", background=[("active", ACCENT_CYAN_HOVER), ("disabled", "#334155")])

        style.configure(
            "Secondary.TButton",
            background=BG_CARD,
            foreground=TEXT_PRIMARY,
            font=(FONT_FAMILY, 9),
            borderwidth=1,
            relief="solid",
            padding=(10, 5),
        )
        style.map("Secondary.TButton", background=[("active", "#334155")])

        # Entry style
        style.configure(
            "TEntry",
            fieldbackground=BG_ENTRY,
            foreground=TEXT_PRIMARY,
            insertcolor=ACCENT_CYAN,
            padding=6,
            relief="flat",
        )

        # Notebook tabs style
        style.configure("TNotebook", background=BG_DARK, borderwidth=0)
        style.configure(
            "TNotebook.Tab",
            background=BG_CARD,
            foreground=TEXT_MUTED,
            padding=(14, 8),
            font=(FONT_FAMILY, 10, "bold"),
            borderwidth=0,
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", ACCENT_CYAN), ("active", "#334155")],
            foreground=[("selected", "#000000"), ("active", TEXT_PRIMARY)],
        )

        # Progressbar
        style.configure("Horizontal.TProgressbar", troughcolor=BG_ENTRY, background=ACCENT_CYAN, thickness=6)

    def _build_header(self):
        header_frame = ttk.Frame(self.root, padding=(16, 12, 16, 4))
        header_frame.pack(fill="x")

        title_lbl = ttk.Label(header_frame, text="⚡ OSINT RECON SCANNER", style="Header.TLabel")
        title_lbl.pack(side="left")

        sub_lbl = ttk.Label(
            header_frame,
            text="Passive Intelligence Gathering • WHOIS • DNS • GeoIP • Shodan • Subdomains • Leaks",
            style="SubHeader.TLabel",
        )
        sub_lbl.pack(side="left", padx=(12, 0), pady=(4, 0))

    def _build_toolbar(self):
        bar = ttk.Frame(self.root, padding=(16, 6))
        bar.pack(fill="x")

        # Input Card Container
        card = ttk.Frame(bar, style="Card.TFrame", padding=(12, 10))
        card.pack(fill="x")

        ttk.Label(card, text="Target Domain(s):", font=(FONT_FAMILY, 10, "bold"), background=BG_CARD).pack(side="left")

        self.domain_var = tk.StringVar()
        self.entry = ttk.Entry(card, textvariable=self.domain_var, width=38, font=(MONO_FONT, 10))
        self.entry.pack(side="left", padx=(8, 10))
        self.entry.insert(0, "example.com")
        self.entry.bind("<FocusIn>", self._clear_placeholder)
        self.entry.bind("<Return>", lambda _e: self.start_scan())

        self.scan_btn = ttk.Button(card, text="🚀 Start Scan", style="Primary.TButton", command=self.start_scan)
        self.scan_btn.pack(side="left", padx=(0, 6))

        self.load_btn = ttk.Button(card, text="📁 Load List", style="Secondary.TButton", command=self.load_file)
        self.load_btn.pack(side="left", padx=(0, 6))

        self.clear_btn = ttk.Button(card, text="🧹 Clear", style="Secondary.TButton", command=self.clear_results)
        self.clear_btn.pack(side="left")

        # Action Buttons Right
        self.open_json_btn = ttk.Button(
            card, text="📄 Open JSON", style="Secondary.TButton", command=self.open_json, state="disabled"
        )
        self.open_json_btn.pack(side="right")

        self.open_dir_btn = ttk.Button(
            card, text="📂 Results Folder", style="Secondary.TButton", command=self.open_results_dir
        )
        self.open_dir_btn.pack(side="right", padx=(0, 6))

        self.copy_tab_btn = ttk.Button(
            card, text="📋 Copy Tab", style="Secondary.TButton", command=self.copy_current_tab
        )
        self.copy_tab_btn.pack(side="right", padx=(0, 6))

    def _clear_placeholder(self, event):
        if self.domain_var.get() == "example.com":
            self.domain_var.set("")

    def _build_tabs(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=16, pady=(10, 4))

        self.text_widgets = {}
        for label, key in TABS:
            frame = ttk.Frame(self.notebook, background=BG_DARK)
            self.notebook.add(frame, text=label)

            text_frame = ttk.Frame(frame)
            text_frame.pack(fill="both", expand=True, pady=4)

            # Scrollbars
            scrollbar = ttk.Scrollbar(text_frame, orient="vertical")
            text = tk.Text(
                text_frame,
                wrap="word",
                relief="flat",
                padx=14,
                pady=10,
                bg=BG_CARD,
                fg=TEXT_PRIMARY,
                insertbackground=ACCENT_CYAN,
                font=(MONO_FONT, 9.5),
                yscrollcommand=scrollbar.set,
                selectbackground=ACCENT_CYAN,
                selectforeground="#000000",
            )
            scrollbar.config(command=text.yview)
            scrollbar.pack(side="right", fill="y")
            text.pack(side="left", fill="both", expand=True)

            self._configure_text_tags(text)
            self.text_widgets[key] = text

    def _configure_text_tags(self, text_widget: tk.Text):
        text_widget.tag_configure("header", foreground=ACCENT_CYAN, font=(FONT_FAMILY, 11, "bold"))
        text_widget.tag_configure("subheader", foreground=ACCENT_BLUE, font=(FONT_FAMILY, 10, "bold"))
        text_widget.tag_configure("label", foreground=ACCENT_CYAN, font=(MONO_FONT, 9, "bold"))
        text_widget.tag_configure("value", foreground=TEXT_PRIMARY, font=(MONO_FONT, 9))
        text_widget.tag_configure("success", foreground=COLOR_SUCCESS, font=(MONO_FONT, 9, "bold"))
        text_widget.tag_configure("warning", foreground=COLOR_WARNING, font=(MONO_FONT, 9, "bold"))
        text_widget.tag_configure("error", foreground=COLOR_ERROR, font=(MONO_FONT, 9, "bold"))
        text_widget.tag_configure("muted", foreground=TEXT_MUTED, font=(MONO_FONT, 9))
        text_widget.tag_configure("ip", foreground="#38BDF8", font=(MONO_FONT, 9, "bold"))
        text_widget.tag_configure("subdomain", foreground="#A78BFA", font=(MONO_FONT, 9))

    def _build_statusbar(self):
        bar_frame = ttk.Frame(self.root, style="Card.TFrame", padding=(16, 6))
        bar_frame.pack(fill="x", side="bottom")

        self.pulse_lbl = tk.Label(bar_frame, text="🟢", bg=BG_CARD, fg=COLOR_SUCCESS, font=(FONT_FAMILY, 10))
        self.pulse_lbl.pack(side="left", padx=(0, 4))

        self.status_var = tk.StringVar(value="Ready. Enter target domain(s) and press Start Scan.")
        ttk.Label(bar_frame, textvariable=self.status_var, style="Status.TLabel").pack(side="left")

        self.progress = ttk.Progressbar(bar_frame, mode="determinate", length=220, style="Horizontal.TProgressbar")
        self.progress.pack(side="right")

    def _bind_shortcuts(self):
        self.root.bind("<Control-c>", lambda _e: self.copy_current_tab())
        self.root.bind("<Control-l>", lambda _e: self.entry.focus_set())

    def copy_current_tab(self):
        current_tab_id = self.notebook.select()
        if not current_tab_id:
            return
        current_idx = self.notebook.index(current_tab_id)
        _, key = TABS[current_idx]
        text_widget = self.text_widgets[key]
        content = text_widget.get("1.0", "end-1c").strip()
        if content:
            self.root.clipboard_clear()
            self.root.clipboard_append(content)
            self.status_var.set("Copied current tab contents to clipboard!")

    def clear_results(self):
        for text in self.text_widgets.values():
            text.delete("1.0", "end")
        self._results = {}
        self._json_path = None
        self.open_json_btn.config(state="disabled")
        self.status_var.set("Cleared search results.")
        self.pulse_lbl.config(text="🟢", fg=COLOR_SUCCESS)

    def load_file(self):
        path = filedialog.askopenfilename(title="Select domain list", filetypes=[("Text files", "*.txt")])
        if not path:
            return
        try:
            with open(path, encoding="utf-8-sig") as fh:
                domains = [sanitize_domain(line) for line in fh if line.strip()]
                domains = [d for d in domains if d]
        except OSError as exc:
            messagebox.showerror("Load failed", str(exc))
            return
        if not domains:
            messagebox.showwarning("Empty file", "No valid domains found in the selected file.")
            return
        self.domain_var.set(", ".join(domains))
        self._domain_list = domains

    def start_scan(self):
        if self._scanning:
            return
        raw = self.domain_var.get().strip()
        if raw and raw != "example.com":
            tokens = re.split(r"[,\s]+", raw)
            self._domain_list = [sanitize_domain(d) for d in tokens if sanitize_domain(d)]

        if not self._domain_list:
            messagebox.showwarning("No Target", "Please enter a valid domain or load a domain list file.")
            return

        for text in self.text_widgets.values():
            text.delete("1.0", "end")
        self._results = {}
        self._scanning = True
        self.scan_btn.config(state="disabled")
        self.load_btn.config(state="disabled")
        self.clear_btn.config(state="disabled")
        self.open_json_btn.config(state="disabled")
        self.pulse_lbl.config(text="⚡", fg=ACCENT_CYAN)

        total_steps = len(self._domain_list) * (len(TABS) - 1)
        self.progress.config(maximum=total_steps, value=0)
        self.status_var.set(f"Initializing scan for {len(self._domain_list)} domain(s)...")

        threading.Thread(target=self._scan_worker, daemon=True).start()

    def _scan_worker(self):
        done = 0
        for domain in self._domain_list:
            self.root.after(0, self._set_status, f"Scanning target: {domain}...")
            self._results[domain] = {}

            for name, scan_fn in MODULES.items():
                try:
                    res = scan_fn(domain)
                except Exception as exc:
                    res = {"error": str(exc)}
                self._results[domain][name] = res
                done += 1
                self.root.after(0, self._set_progress, done)
                self.root.after(0, self._render_tab, domain, name, res)

            # Render Overview tab summary after all modules for this domain complete
            self.root.after(0, self._render_overview, domain, self._results[domain])

        self.root.after(0, self._scan_finished)

    def _render_tab(self, domain: str, name: str, result: dict):
        text = self.text_widgets[name]
        text.insert("end", f"▶ Target: ", "subheader")
        text.insert("end", f"{domain}\n", "header")

        for label, key in FIELDS[name]:
            value = result.get(key, "N/A")
            text.insert("end", f"{label:<20}: ", "label")
            formatted = _format_value(value)

            if key == "ip" and formatted != "N/A":
                text.insert("end", f"{formatted}\n\n", "ip")
            elif key == "subdomains":
                for sub in result.get("subdomains", []):
                    text.insert("end", f"  • {sub}\n", "subdomain")
                if not result.get("subdomains"):
                    text.insert("end", "none\n", "muted")
                text.insert("end", "\n")
            else:
                text.insert("end", f"{formatted}\n\n", "value")

        error = result.get("error")
        if error and error not in ("N/A", "none", None):
            text.insert("end", f"Notice / Warning     : ", "warning")
            text.insert("end", f"{error}\n", "error")

        text.insert("end", "─" * 60 + "\n\n", "muted")
        text.see("end")

    def _render_overview(self, domain: str, scan_data: dict):
        text = self.text_widgets["overview"]
        text.insert("end", f"🌐 TARGET SUMMARY REPORT: ", "subheader")
        text.insert("end", f"{domain}\n", "header")
        text.insert("end", f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n", "muted")

        # WHOIS summary
        w = scan_data.get("whois", {})
        text.insert("end", "• WHOIS Registrar   : ", "label")
        text.insert("end", f"{w.get('registrar', 'N/A')}\n", "value")

        # GeoIP summary
        g = scan_data.get("geoip", {})
        text.insert("end", "• Resolved IP       : ", "label")
        text.insert("end", f"{g.get('ip', 'N/A')}", "ip")
        text.insert("end", f" ({g.get('city', 'N/A')}, {g.get('country', 'N/A')})\n", "value")

        # Subdomain count
        sd = scan_data.get("subdomains", {}).get("subdomains", [])
        text.insert("end", "• Discovered Subs   : ", "label")
        text.insert("end", f"{len(sd)} subdomains found\n", "success" if sd else "muted")

        # Shodan open ports
        ports = scan_data.get("shodan", {}).get("ports", [])
        text.insert("end", "• Shodan Open Ports : ", "label")
        text.insert("end", f"{', '.join(str(p) for p in ports) if ports else 'none'}\n", "warning" if ports else "value")

        # Leaks
        github_count = len(scan_data.get("leaks", {}).get("github_leaks", []))
        breaches = scan_data.get("leaks", {}).get("email_leaks", 0)
        text.insert("end", "• Leak Exposures     : ", "label")
        text.insert(
            "end",
            f"GitHub Code Hits: {github_count} | HIBP Breaches: {breaches}\n",
            "error" if (github_count or breaches) else "success",
        )

        text.insert("end", "\n" + "═" * 60 + "\n\n", "muted")
        text.see("end")

    def _set_status(self, message):
        self.status_var.set(message)

    def _set_progress(self, value):
        self.progress.config(value=value)

    def _scan_finished(self):
        self._scanning = False
        self.scan_btn.config(state="normal")
        self.load_btn.config(state="normal")
        self.clear_btn.config(state="normal")
        self.pulse_lbl.config(text="🟢", fg=COLOR_SUCCESS)

        domains_payload = [{"domain": d, **self._results[d]} for d in self._results]
        scan_time = timestamp_now()

        try:
            self._json_path = write_json(scan_time, domains_payload)
            self.open_json_btn.config(state="normal")
            self.status_var.set(f"Scan complete! Report generated: {self._json_path}")
        except Exception as exc:
            self.status_var.set(f"Scan complete. Failed to write JSON: {exc}")

    def open_json(self):
        if self._json_path and os.path.exists(self._json_path):
            webbrowser.open(self._json_path)

    def open_results_dir(self):
        try:
            if os.name == "nt":
                subprocess.Popen(["explorer", str(OUTPUT_DIR)])
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(OUTPUT_DIR)])
            else:
                subprocess.Popen(["xdg-open", str(OUTPUT_DIR)])
        except OSError as exc:
            messagebox.showerror("Open failed", str(exc))


def main() -> int:
    try:
        root = tk.Tk()
    except tk.TclError as exc:
        print("\n[!] GUI Launch Error: No X11/Tkinter display detected ($DISPLAY is not set).")
        print("💡 Usage alternative: Run the CLI version instead using:")
        print("    python3 scanner.py <domain>\n")
        return 1

    app = OSINTGui(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
