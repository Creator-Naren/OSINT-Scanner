"""Tkinter GUI for the OSINT scanner."""

import subprocess
import sys
import threading
import webbrowser

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from osint_scanner.modules import MODULES
from osint_scanner.output import OUTPUT_DIR, write_json

TABS = [
    ("WHOIS", "whois"),
    ("DNS", "dns"),
    ("GeoIP", "geoip"),
    ("Shodan", "shodan"),
    ("Subdomains", "subdomains"),
    ("Leaks", "leaks"),
]

FIELDS = {
    "whois": [
        ("Registrar", "registrar"),
        ("Created", "creation_date"),
        ("Expires", "expiration_date"),
        ("Name servers", "name_servers"),
        ("Emails", "emails"),
    ],
    "dns": [
        ("A", "A"),
        ("AAAA", "AAAA"),
        ("MX", "MX"),
        ("NS", "NS"),
        ("TXT", "TXT"),
        ("CNAME", "CNAME"),
        ("SOA", "SOA"),
    ],
    "geoip": [
        ("IP", "ip"),
        ("City", "city"),
        ("Region", "region"),
        ("Country", "country"),
        ("ISP", "isp"),
        ("AS", "as"),
        ("Latitude", "lat"),
        ("Longitude", "lon"),
    ],
    "shodan": [
        ("Ports", "ports"),
        ("Hostnames", "hostnames"),
        ("Vulns", "vulns"),
        ("OS", "os"),
    ],
    "subdomains": [("Found subdomains", "subdomains")],
    "leaks": [("GitHub hits", "github_leaks"), ("Breach domains", "email_leaks")],
}


def _format_value(value) -> str:
    if isinstance(value, list):
        if not value:
            return "none"
        if isinstance(value[0], dict):
            lines = []
            for item in value:
                lines.append(f"- {item.get('repository')} / {item.get('path')}\n  {item.get('html_url')}")
            return "\n".join(lines)
        return "\n".join(str(v) for v in value)
    return str(value)


class OSINTGui:
    def __init__(self, root):
        self.root = root
        root.title("OSINT Scanner")
        root.geometry("900x640")
        root.minsize(700, 480)

        self._scanning = False
        self._results = None
        self._json_path = None

        self._build_toolbar()
        self._build_tabs()
        self._build_statusbar()

    def _build_toolbar(self):
        bar = ttk.Frame(self.root, padding=(8, 6))
        bar.pack(fill="x")

        ttk.Label(bar, text="Domain:").pack(side="left")
        self.domain_var = tk.StringVar()
        entry = ttk.Entry(bar, textvariable=self.domain_var, width=32)
        entry.pack(side="left", padx=(6, 8))
        entry.bind("<Return>", lambda _e: self.start_scan())

        self.scan_btn = ttk.Button(bar, text="Scan", command=self.start_scan)
        self.scan_btn.pack(side="left")

        self.load_btn = ttk.Button(bar, text="Load file", command=self.load_file)
        self.load_btn.pack(side="left", padx=(6, 0))

        self.open_json_btn = ttk.Button(bar, text="Open JSON", command=self.open_json, state="disabled")
        self.open_json_btn.pack(side="right")

        self.open_dir_btn = ttk.Button(bar, text="Results folder", command=self.open_results_dir)
        self.open_dir_btn.pack(side="right", padx=(0, 6))

    def _build_tabs(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=8, pady=(0, 4))

        self.text_widgets = {}
        for label, key in TABS:
            frame = ttk.Frame(self.notebook)
            self.notebook.add(frame, text=label)
            text = tk.Text(frame, wrap="word", relief="flat", padx=10, pady=8)
            text.pack(fill="both", expand=True)
            self.text_widgets[key] = text

    def _build_statusbar(self):
        bar = ttk.Frame(self.root, padding=(8, 4))
        bar.pack(fill="x", side="bottom")

        self.status_var = tk.StringVar(value="Ready. Enter a domain and press Scan.")
        ttk.Label(bar, textvariable=self.status_var).pack(side="left")

        self.progress = ttk.Progressbar(bar, mode="determinate", length=180)
        self.progress.pack(side="right")

    def load_file(self):
        path = filedialog.askopenfilename(title="Select domain list", filetypes=[("Text files", "*.txt")])
        if not path:
            return
        try:
            with open(path, encoding="utf-8-sig") as fh:
                domains = [line.strip() for line in fh if line.strip()]
        except OSError as exc:
            messagebox.showerror("Load failed", str(exc))
            return
        if not domains:
            messagebox.showwarning("Empty file", "No domains found in the selected file.")
            return
        self.domain_var.set(", ".join(domains))
        self._domain_list = domains

    def start_scan(self):
        if self._scanning:
            return
        raw = self.domain_var.get().strip()
        if raw:
            self._domain_list = [d.strip() for d in raw.replace(",", " ").split() if d.strip()]
        if not self._domain_list:
            messagebox.showwarning("No domain", "Enter a domain or load a file first.")
            return

        for text in self.text_widgets.values():
            text.delete("1.0", "end")
        self._results = {}
        self._scanning = True
        self.scan_btn.config(state="disabled")
        self.load_btn.config(state="disabled")
        self.open_json_btn.config(state="disabled")
        self.progress.config(maximum=len(self._domain_list) * len(TABS), value=0)
        self.status_var.set(f"Scanning {len(self._domain_list)} domain(s)...")
        threading.Thread(target=self._scan_worker, daemon=True).start()

    def _scan_worker(self):
        if self._results is None:
            self._results = {}
        done = 0
        for domain in self._domain_list:
            self.root.after(0, self._set_status, f"Scanning {domain}...")
            for name, scan in MODULES.items():
                try:
                    result = scan(domain)
                except Exception as exc:
                    result = {"error": str(exc)}
                self._results[domain] = self._results.get(domain, {})
                self._results[domain][name] = result
                done += 1
                self.root.after(0, self._set_progress, done)
                self.root.after(0, self._render_tab, domain, name, result)
        self.root.after(0, self._scan_finished)

    def _render_tab(self, domain, name, result):
        text = self.text_widgets[name]
        text.insert("end", f"[{domain}]\n")
        for label, key in FIELDS[name]:
            value = result.get(key, "N/A")
            text.insert("end", f"{label}: {_format_value(value)}\n\n")
        error = result.get("error")
        if error and error not in ("N/A", "none"):
            text.insert("end", f"Error: {error}\n")
        text.insert("end", "-" * 50 + "\n\n")
        text.see("end")

    def _set_status(self, message):
        self.status_var.set(message)

    def _set_progress(self, value):
        self.progress.config(value=value)

    def _scan_finished(self):
        self._scanning = False
        self.scan_btn.config(state="normal")
        self.load_btn.config(state="normal")
        domains = [{"domain": d, **self._results[d]} for d in self._results]
        from osint_scanner.output import timestamp_now

        self._json_path = write_json(timestamp_now(), domains)
        self.open_json_btn.config(state="normal")
        self.status_var.set(f"Done. Results written to {self._json_path}")

    def open_json(self):
        if self._json_path:
            webbrowser.open(self._json_path)

    def open_results_dir(self):
        try:
            subprocess.Popen(["explorer", str(OUTPUT_DIR)])
        except OSError as exc:
            messagebox.showerror("Open failed", str(exc))


def main() -> int:
    root = tk.Tk()
    OSINTGui(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
