#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
System Info Collector (Cybersecurity Practical)
Author: Ahmed-ready template
License: MIT

Features:
- Cross-platform (Windows / macOS / Linux)
- Collects local IP, public IP, MAC address, and Wi-Fi password
- CLI or simple GUI mode
"""

import platform
import re
import socket
import subprocess
import sys
from dataclasses import dataclass
from typing import Optional

import psutil  # pip install psutil
import requests  # pip install requests

TIMEOUT = 4  # seconds for network requests


@dataclass
class WifiInfo:
    ssid: Optional[str]
    password: Optional[str]
    note: Optional[str] = None


class SystemInfo:
    """Collects system/network info for cybersecurity tasks."""

    def __init__(self) -> None:
        self._os = platform.system()

    # --------------------------
    # Local and Public IP
    # --------------------------
    def get_local_ip(self) -> str:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except Exception:
            return socket.gethostbyname(socket.gethostname())

    def get_public_ip(self) -> Optional[str]:
        providers = [
            "https://api.ipify.org",
            "https://ifconfig.me/ip",
            "https://ip.seeip.org",
            "https://ipv4.icanhazip.com",
        ]
        for url in providers:
            try:
                r = requests.get(url, timeout=TIMEOUT)
                if r.ok:
                    ip = r.text.strip()
                    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
                        return ip
            except Exception:
                continue
        return None

    # --------------------------
    # MAC Address
    # --------------------------
    def get_mac_address(self) -> Optional[str]:
        local_ip = self.get_local_ip()
        addrs = psutil.net_if_addrs()

        iface_of_ip = None
        for iface, infos in addrs.items():
            for info in infos:
                if getattr(info, "address", None) == local_ip:
                    iface_of_ip = iface
                    break
            if iface_of_ip:
                break

        if iface_of_ip:
            for info in addrs.get(iface_of_ip, []):
                if hasattr(psutil, "AF_LINK") and info.family == psutil.AF_LINK:
                    if info.address and len(info.address.split(":")) == 6:
                        return info.address
        else:
            for iface, infos in addrs.items():
                stats = psutil.net_if_stats().get(iface)
                if stats and stats.isup:
                    for info in infos:
                        if hasattr(psutil, "AF_LINK") and info.family == psutil.AF_LINK:
                            if info.address and len(info.address.split(":")) == 6:
                                return info.address
        return None

    # --------------------------
    # Wi-Fi Password
    # --------------------------
    def get_wifi_password(self) -> WifiInfo:
        osname = self._os
        try:
            if osname == "Windows":
                return self._wifi_password_windows()
            elif osname == "Darwin":
                return self._wifi_password_macos()
            elif osname == "Linux":
                return self._wifi_password_linux()
            else:
                return WifiInfo(None, None, note=f"Unsupported OS: {osname}")
        except Exception as e:
            return WifiInfo(None, None, note=f"Error: {e}")

    def _wifi_password_windows(self) -> WifiInfo:
        out = subprocess.check_output(["netsh", "wlan", "show", "interfaces"], text=True, encoding="utf-8", errors="ignore")
        m = re.search(r"^\s*SSID\s*:\s*(.+)$", out, re.MULTILINE)
        ssid = m.group(1).strip() if m else None
        if not ssid:
            return WifiInfo(None, None, note="No active Wi-Fi interface found.")

        out = subprocess.check_output(["netsh", "wlan", "show", "profile", f"name={ssid}", "key=clear"], text=True, encoding="utf-8", errors="ignore")
        m = re.search(r"^\s*Key Content\s*:\s*(.+)$", out, re.MULTILINE)
        pwd = m.group(1).strip() if m else None
        note = None if pwd else "Profile found but no key content (open or restricted network)."
        return WifiInfo(ssid, pwd, note)

    def _wifi_password_macos(self) -> WifiInfo:
        ssid = None
        try:
            out = subprocess.check_output(["/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", "-I"], text=True)
            m = re.search(r"^\s*SSID:\s*(.+)$", out, re.MULTILINE)
            if m:
                ssid = m.group(1).strip()
        except Exception:
            pass

        if not ssid:
            return WifiInfo(None, None, note="Could not detect SSID.")

        try:
            pwd = subprocess.check_output(
                ["security", "find-generic-password", "-D", "AirPort network password", "-a", ssid, "-gw"],
                text=True,
                stderr=subprocess.DEVNULL,
            ).strip()
            return WifiInfo(ssid, pwd or None, None if pwd else "Not found in keychain.")
        except subprocess.CalledProcessError:
            return WifiInfo(ssid, None, note="Permission denied or not found.")

    def _wifi_password_linux(self) -> WifiInfo:
        try:
            out = subprocess.check_output(["nmcli", "-t", "-f", "active,ssid", "dev", "wifi"], text=True)
            ssid = None
            for line in out.splitlines():
                if line.startswith("yes:"):
                    ssid = line.split(":", 1)[1].strip()
                    break
            if not ssid:
                return WifiInfo(None, None, note="No active Wi-Fi detected.")
        except FileNotFoundError:
            return WifiInfo(None, None, note="nmcli not installed.")
        except Exception as e:
            return WifiInfo(None, None, note=f"Error: {e}")

        try:
            out = subprocess.check_output(["nmcli", "-s", "-g", "802-11-wireless-security.psk", "connection", "show", ssid], text=True)
            pwd = out.strip() or None
            return WifiInfo(ssid, pwd, None if pwd else "No PSK stored or permission needed.")
        except subprocess.CalledProcessError:
            return WifiInfo(ssid, None, note="Cannot read PSK.")

    # --------------------------
    # Summary
    # --------------------------
    def summarize(self) -> str:
        local_ip = self.get_local_ip()
        public_ip = self.get_public_ip() or "Unavailable"
        mac = self.get_mac_address() or "Unavailable"
        wifi = self.get_wifi_password()

        result = [
            f"Operating System : {self._os}",
            f"Local IP         : {local_ip}",
            f"Public IP        : {public_ip}",
            f"MAC Address      : {mac}",
            f"Wi-Fi SSID       : {wifi.ssid or 'Unknown'}",
            f"Wi-Fi Password   : {wifi.password or 'Unavailable'}",
        ]
        if wifi.note:
            result.append(f"Note             : {wifi.note}")
        return "\n".join(result)


# --------------------------
# CLI / GUI entry points
# --------------------------
def _run_cli() -> None:
    s = SystemInfo()
    print(s.summarize())


def _run_gui() -> None:
    try:
        import tkinter as tk
    except Exception:
        print("Tkinter not available, running CLI instead.")
        _run_cli()
        return

    si = SystemInfo()

    root = tk.Tk()
    root.title("System Info Collector")

    text = tk.Text(root, width=70, height=12)
    text.pack(padx=12, pady=12)

    def refresh():
        text.delete("1.0", tk.END)
        text.insert(tk.END, si.summarize())

    tk.Button(root, text="Refresh", command=refresh).pack(pady=(0, 12))
    refresh()
    root.mainloop()


if name == "__main__":
    if "--gui" in sys.argv:
        _run_gui()
    else:
        _run_cli()
