# -*- coding: utf-8 -*-
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import ttk

import customtkinter as ctk

from dpwo import NETOwner

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("green")


def detect_interfaces():
    platform = sys.platform
    try:
        if platform == "linux" or platform == "linux2":
            out = subprocess.check_output(
                ["nmcli", "-t", "-f", "DEVICE,TYPE", "device", "status"],
                text=True, timeout=10,
            )
            return [
                line.split(":")[0]
                for line in out.strip().splitlines()
                if "wifi" in line.split(":")[1]
            ] or ["wlp3s0"]
        elif platform == "darwin":
            out = subprocess.check_output(
                ["networksetup", "-listallhardwareports"],
                text=True, timeout=10,
            )
            ifaces = []
            lines = out.splitlines()
            for i, line in enumerate(lines):
                if "Wi-Fi" in line or "AirPort" in line:
                    for j in range(i + 1, min(i + 3, len(lines))):
                        if lines[j].startswith("Device:"):
                            ifaces.append(lines[j].split(":")[1].strip())
            return ifaces or ["en0"]
        elif platform == "win32":
            out = subprocess.check_output(
                ["netsh", "wlan", "show", "interfaces"],
                text=True, timeout=10,
            )
            ifaces = []
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("Name"):
                    ifaces.append(line.split(":", 1)[1].strip())
            return ifaces or ["Wi-Fi"]
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError, IndexError):
        pass

    if platform == "win32":
        return ["Wi-Fi"]
    return ["wlp3s0"]


class DPWOApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("DPWO - Free WiFi")
        self.geometry("700x600")
        self.minsize(600, 500)

        self._scanning = False
        self._owner = None
        self._results = []

        self._build_ui()

    def _build_ui(self):
        # -- Top controls --
        top = ctk.CTkFrame(self)
        top.pack(fill="x", padx=15, pady=(15, 5))

        ctk.CTkLabel(top, text="Interface:").pack(side="left", padx=(10, 5))
        ifaces = detect_interfaces()
        self._iface_var = ctk.StringVar(value=ifaces[0])
        self._iface_menu = ctk.CTkOptionMenu(
            top, variable=self._iface_var, values=ifaces, width=150
        )
        self._iface_menu.pack(side="left", padx=5)

        self._brute_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(top, text="Brute force", variable=self._brute_var).pack(
            side="left", padx=20
        )

        self._autoconnect_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(
            top, text="Auto-connect", variable=self._autoconnect_var
        ).pack(side="left", padx=5)

        # -- Scan button --
        self._scan_btn = ctk.CTkButton(
            self,
            text="Scan & Connect",
            height=45,
            font=ctk.CTkFont(size=16, weight="bold"),
            command=self._on_scan_click,
        )
        self._scan_btn.pack(fill="x", padx=15, pady=10)

        # -- Status / progress --
        status_frame = ctk.CTkFrame(self)
        status_frame.pack(fill="x", padx=15, pady=(0, 5))

        self._status_label = ctk.CTkLabel(
            status_frame, text="Ready. Click Scan & Connect to start."
        )
        self._status_label.pack(side="left", padx=10, pady=5)

        self._progress = ctk.CTkProgressBar(status_frame, width=200)
        self._progress.pack(side="right", padx=10, pady=5)
        self._progress.set(0)

        # -- Results table --
        table_frame = ctk.CTkFrame(self)
        table_frame.pack(fill="both", expand=True, padx=15, pady=5)

        ctk.CTkLabel(
            table_frame, text="Found Networks:", font=ctk.CTkFont(weight="bold")
        ).pack(anchor="w", padx=10, pady=(5, 0))

        style = ttk.Style()
        style.theme_use("clam")
        style.configure(
            "Dark.Treeview",
            background="#2b2b2b",
            foreground="white",
            fieldbackground="#2b2b2b",
            rowheight=28,
        )
        style.configure(
            "Dark.Treeview.Heading",
            background="#333333",
            foreground="white",
        )
        style.map("Dark.Treeview", background=[("selected", "#1f6aa5")])

        tree_container = tk.Frame(table_frame, bg="#2b2b2b")
        tree_container.pack(fill="both", expand=True, padx=10, pady=5)

        self._tree = ttk.Treeview(
            tree_container,
            columns=("ssid", "password", "status"),
            show="headings",
            selectmode="browse",
            style="Dark.Treeview",
        )
        self._tree.heading("ssid", text="SSID")
        self._tree.heading("password", text="Password")
        self._tree.heading("status", text="Status")
        self._tree.column("ssid", width=220)
        self._tree.column("password", width=220)
        self._tree.column("status", width=180)

        scrollbar = ttk.Scrollbar(
            tree_container, orient="vertical", command=self._tree.yview
        )
        self._tree.configure(yscrollcommand=scrollbar.set)
        self._tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # -- Action buttons --
        btn_frame = ctk.CTkFrame(self)
        btn_frame.pack(fill="x", padx=15, pady=5)

        self._copy_btn = ctk.CTkButton(
            btn_frame, text="Copy Password", command=self._on_copy, state="disabled"
        )
        self._copy_btn.pack(side="left", padx=10, pady=5)

        self._connect_btn = ctk.CTkButton(
            btn_frame,
            text="Connect to Selected",
            command=self._on_connect_selected,
            state="disabled",
        )
        self._connect_btn.pack(side="left", padx=10, pady=5)

        # -- Log panel --
        log_frame = ctk.CTkFrame(self)
        log_frame.pack(fill="x", padx=15, pady=(5, 15))

        ctk.CTkLabel(
            log_frame, text="Log:", font=ctk.CTkFont(weight="bold")
        ).pack(anchor="w", padx=10, pady=(5, 0))

        self._log_text = ctk.CTkTextbox(log_frame, height=90)
        self._log_text.pack(fill="x", padx=10, pady=5)
        self._log_text.configure(state="disabled")

    # -- Logging --

    def _log(self, msg):
        self._log_text.configure(state="normal")
        self._log_text.insert("end", msg + "\n")
        self._log_text.see("end")
        self._log_text.configure(state="disabled")

    def _set_status(self, text):
        self._status_label.configure(text=text)

    # -- Scan logic --

    def _on_scan_click(self):
        if self._scanning:
            return

        self._scanning = True
        self._results = []
        self._scan_btn.configure(state="disabled", text="Scanning...")
        self._copy_btn.configure(state="disabled")
        self._connect_btn.configure(state="disabled")
        self._progress.configure(mode="indeterminate")
        self._progress.start()

        for item in self._tree.get_children():
            self._tree.delete(item)

        self._set_status("Scanning for networks...")
        self._log(f"Scanning on {self._iface_var.get()}...")

        self._owner = NETOwner(
            self._iface_var.get(),
            connect=False,
            brute=self._brute_var.get(),
            log_callback=lambda msg: self.after(0, self._log, msg),
        )
        self._log(f"Loaded {len(self._owner.plugins)} plugins.")

        thread = threading.Thread(target=self._scan_thread, daemon=True)
        thread.start()

    def _scan_thread(self):
        self._owner.scan_network_with_callback(
            on_result=lambda r: self.after(0, self._add_result, r),
            on_done=lambda results: self.after(0, self._scan_done, results),
            on_error=lambda err: self.after(0, self._scan_error, err),
        )

    def _add_result(self, wifi):
        self._results.append(wifi)
        self._tree.insert(
            "", "end",
            values=(wifi["ssid"], wifi["wifi_password"], "--"),
        )
        self._log(f"Found: {wifi['ssid']}")

    def _scan_done(self, results):
        self._progress.stop()
        self._progress.configure(mode="determinate")
        self._progress.set(1.0)
        self._scanning = False

        if not results:
            self._set_status("No vulnerable networks found.")
            self._scan_btn.configure(state="normal", text="Scan & Connect")
            self._log("Scan complete. No vulnerable networks found.")
            return

        self._set_status(f"Found {len(results)} network(s).")
        self._copy_btn.configure(state="normal")
        self._connect_btn.configure(state="normal")
        self._log(f"Scan complete. Found {len(results)} vulnerable network(s).")

        if self._autoconnect_var.get():
            self._set_status("Auto-connecting to best network...")
            thread = threading.Thread(
                target=self._autoconnect_thread, daemon=True
            )
            thread.start()
        else:
            self._scan_btn.configure(state="normal", text="Scan & Connect")

    def _scan_error(self, err):
        self._progress.stop()
        self._progress.configure(mode="determinate")
        self._progress.set(0)
        self._scanning = False
        self._set_status(f"Scan error: {err}")
        self._scan_btn.configure(state="normal", text="Scan & Connect")
        self._log(f"Error: {err}")

    # -- Connection logic --

    def _autoconnect_thread(self):
        for i, wifi in enumerate(self._results):
            self.after(0, self._log, f"Trying to connect to {wifi['ssid']}...")
            self.after(0, self._update_row_status, i, "Connecting...")
            status = self._owner.connect_and_verify(wifi)
            if status == "connected":
                self.after(0, self._update_row_status, i, "Connected!")
                self.after(0, self._set_status, f"Connected to {wifi['ssid']}!")
                self.after(0, self._log, f"Connected and verified: {wifi['ssid']}")
                self.after(0, self._finish_connect)
                return
            elif status == "no_internet":
                self.after(0, self._update_row_status, i, "No internet")
                self.after(0, self._log, f"{wifi['ssid']}: connected but no internet")
            else:
                self.after(0, self._update_row_status, i, "Failed")
                self.after(0, self._log, f"{wifi['ssid']}: connection failed")

        self.after(0, self._set_status, "Could not connect to any network.")
        self.after(0, self._finish_connect)

    def _on_connect_selected(self):
        sel = self._tree.selection()
        if not sel:
            return

        idx = self._tree.index(sel[0])
        if idx >= len(self._results):
            return

        wifi = self._results[idx]
        self._connect_btn.configure(state="disabled")
        self._set_status(f"Connecting to {wifi['ssid']}...")

        owner = NETOwner(
            self._iface_var.get(),
            connect=False,
            brute=False,
            log_callback=lambda msg: self.after(0, self._log, msg),
        )

        def connect_thread():
            status = owner.connect_and_verify(wifi)
            if status == "connected":
                self.after(0, self._update_row_status, idx, "Connected!")
                self.after(0, self._set_status, f"Connected to {wifi['ssid']}!")
                self.after(0, self._log, f"Connected and verified: {wifi['ssid']}")
            elif status == "no_internet":
                self.after(0, self._update_row_status, idx, "No internet")
                self.after(0, self._set_status, "Connected but no internet access.")
                self.after(0, self._log, f"{wifi['ssid']}: no internet")
            else:
                self.after(0, self._update_row_status, idx, "Failed")
                self.after(0, self._set_status, "Connection failed.")
                self.after(0, self._log, f"{wifi['ssid']}: failed")
            self.after(0, lambda: self._connect_btn.configure(state="normal"))

        threading.Thread(target=connect_thread, daemon=True).start()

    def _finish_connect(self):
        self._scan_btn.configure(state="normal", text="Scan & Connect")

    def _update_row_status(self, idx, status):
        children = self._tree.get_children()
        if idx < len(children):
            item = children[idx]
            values = self._tree.item(item, "values")
            self._tree.item(item, values=(values[0], values[1], status))

    def _on_copy(self):
        sel = self._tree.selection()
        if not sel:
            return
        values = self._tree.item(sel[0], "values")
        self.clipboard_clear()
        self.clipboard_append(values[1])
        self._set_status(f"Password copied for {values[0]}!")


def main():
    app = DPWOApp()
    app.mainloop()


if __name__ == "__main__":
    main()
