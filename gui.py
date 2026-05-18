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


def _detect_linux_interfaces():
    # Try nmcli
    try:
        out = subprocess.check_output(
            ["nmcli", "-t", "-f", "DEVICE,TYPE", "device", "status"],
            text=True, timeout=10,
        )
        ifaces = [
            line.split(":")[0]
            for line in out.strip().splitlines()
            if "wifi" in line.split(":")[1]
        ]
        if ifaces:
            return ifaces
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        pass

    # Try iwd via busctl
    import re
    try:
        tree = subprocess.check_output(
            ["busctl", "tree", "net.connman.iwd"],
            text=True, timeout=10,
        )
        paths = set(re.findall(r'(/net/connman/iwd/\d+/\d+)\b', tree))
        ifaces = []
        for path in paths:
            try:
                out = subprocess.check_output(
                    [
                        "busctl", "get-property", "net.connman.iwd",
                        path, "net.connman.iwd.Device", "Name",
                    ],
                    text=True, timeout=5,
                )
                match = re.search(r'"(.+)"', out)
                if match:
                    ifaces.append(match.group(1))
            except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
                continue
        if ifaces:
            return ifaces
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        pass

    return ["wlan0"]


def detect_interfaces():
    platform = sys.platform
    try:
        if platform == "linux" or platform == "linux2":
            return _detect_linux_interfaces()
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
    return ["wlan0"]


class DPWOApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("DPWO - WiFi Gratis")
        self.geometry("700x600")
        self.minsize(600, 500)

        self._scanning = False
        self._owner = None
        self._results = []

        self._build_ui()
        self._update_button_label()

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
        ctk.CTkCheckBox(
            top, text="Forca bruta", variable=self._brute_var
        ).pack(side="left", padx=20)

        self._autoconnect_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(
            top, text="Conectar automaticamente",
            variable=self._autoconnect_var,
            command=self._update_button_label,
        ).pack(side="left", padx=5)

        # -- Scan button --
        self._scan_btn = ctk.CTkButton(
            self,
            text="",
            height=45,
            font=ctk.CTkFont(size=16, weight="bold"),
            command=self._on_scan_click,
        )
        self._scan_btn.pack(fill="x", padx=15, pady=10)

        # -- Status / progress --
        status_frame = ctk.CTkFrame(self)
        status_frame.pack(fill="x", padx=15, pady=(0, 5))

        self._status_label = ctk.CTkLabel(
            status_frame, text="Pronto. Clique para iniciar."
        )
        self._status_label.pack(side="left", padx=10, pady=5)

        self._progress = ctk.CTkProgressBar(status_frame, width=200)
        self._progress.pack(side="right", padx=10, pady=5)
        self._progress.set(0)

        # -- Results table --
        table_frame = ctk.CTkFrame(self)
        table_frame.pack(fill="both", expand=True, padx=15, pady=5)

        ctk.CTkLabel(
            table_frame, text="Redes encontradas:",
            font=ctk.CTkFont(weight="bold"),
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
        self._tree.heading("password", text="Senha")
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
            btn_frame, text="Copiar Senha",
            command=self._on_copy, state="disabled",
        )
        self._copy_btn.pack(side="left", padx=10, pady=5)

        self._connect_btn = ctk.CTkButton(
            btn_frame,
            text="Conectar na Selecionada",
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

    # -- Helpers --

    def _update_button_label(self):
        if self._scanning:
            return
        if self._autoconnect_var.get():
            self._scan_btn.configure(text="Buscar e Conectar")
        else:
            self._scan_btn.configure(text="Buscar Redes")

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
        self._scan_btn.configure(state="disabled", text="Buscando...")
        self._copy_btn.configure(state="disabled")
        self._connect_btn.configure(state="disabled")
        self._progress.configure(mode="indeterminate")
        self._progress.start()

        for item in self._tree.get_children():
            self._tree.delete(item)

        self._set_status("Buscando redes...")
        self._log(f"Buscando na interface {self._iface_var.get()}...")

        self._owner = NETOwner(
            self._iface_var.get(),
            connect=False,
            brute=self._brute_var.get(),
            log_callback=lambda msg: self.after(0, self._log, msg),
        )
        self._log(f"{len(self._owner.plugins)} plugins carregados.")

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
        self._log(f"Encontrada: {wifi['ssid']}")

    def _scan_done(self, results):
        self._progress.stop()
        self._progress.configure(mode="determinate")
        self._progress.set(1.0)
        self._scanning = False

        if not results:
            self._set_status("Nenhuma rede vulneravel encontrada.")
            self._update_button_label()
            self._scan_btn.configure(state="normal")
            self._log("Busca concluida. Nenhuma rede vulneravel encontrada.")
            return

        self._set_status(f"{len(results)} rede(s) encontrada(s).")
        self._copy_btn.configure(state="normal")
        self._connect_btn.configure(state="normal")
        self._log(f"Busca concluida. {len(results)} rede(s) vulneravel(is).")

        if self._autoconnect_var.get():
            self._set_status("Conectando automaticamente...")
            thread = threading.Thread(
                target=self._autoconnect_thread, daemon=True
            )
            thread.start()
        else:
            self._update_button_label()
            self._scan_btn.configure(state="normal")

    def _scan_error(self, err):
        self._progress.stop()
        self._progress.configure(mode="determinate")
        self._progress.set(0)
        self._scanning = False
        self._set_status(f"Erro na busca: {err}")
        self._update_button_label()
        self._scan_btn.configure(state="normal")
        self._log(f"Erro: {err}")

    # -- Connection logic --

    def _autoconnect_thread(self):
        for i, wifi in enumerate(self._results):
            self.after(0, self._log, f"Tentando conectar em {wifi['ssid']}...")
            self.after(0, self._update_row_status, i, "Conectando...")
            status = self._owner.connect_and_verify(wifi)
            if status == "connected":
                self.after(0, self._update_row_status, i, "Conectado!")
                self.after(0, self._set_status, f"Conectado em {wifi['ssid']}!")
                self.after(0, self._log, f"Conectado e verificado: {wifi['ssid']}")
                self.after(0, self._finish_connect)
                return
            elif status == "no_internet":
                self.after(0, self._update_row_status, i, "Sem internet")
                self.after(0, self._log, f"{wifi['ssid']}: sem acesso a internet")
            else:
                self.after(0, self._update_row_status, i, "Falhou")
                self.after(0, self._log, f"{wifi['ssid']}: falha na conexao")

        self.after(0, self._set_status, "Nao foi possivel conectar em nenhuma rede.")
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
        self._set_status(f"Conectando em {wifi['ssid']}...")

        owner = NETOwner(
            self._iface_var.get(),
            connect=False,
            brute=False,
            log_callback=lambda msg: self.after(0, self._log, msg),
        )

        def connect_thread():
            status = owner.connect_and_verify(wifi)
            if status == "connected":
                self.after(0, self._update_row_status, idx, "Conectado!")
                self.after(0, self._set_status, f"Conectado em {wifi['ssid']}!")
                self.after(0, self._log, f"Conectado e verificado: {wifi['ssid']}")
            elif status == "no_internet":
                self.after(0, self._update_row_status, idx, "Sem internet")
                self.after(0, self._set_status, "Conectado mas sem acesso a internet.")
                self.after(0, self._log, f"{wifi['ssid']}: sem internet")
            else:
                self.after(0, self._update_row_status, idx, "Falhou")
                self.after(0, self._set_status, "Falha na conexao.")
                self.after(0, self._log, f"{wifi['ssid']}: falhou")
            self.after(0, lambda: self._connect_btn.configure(state="normal"))

        threading.Thread(target=connect_thread, daemon=True).start()

    def _finish_connect(self):
        self._update_button_label()
        self._scan_btn.configure(state="normal")

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
        self._set_status(f"Senha copiada para {values[0]}!")


def main():
    app = DPWOApp()
    app.mainloop()


if __name__ == "__main__":
    main()
