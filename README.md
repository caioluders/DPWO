# DPWO 
*Default Password Wifi Owner*

## WTF ? 
DPWO is a tool for automatically discover passwords of nearby WIFI networks. This is possible due to default passwords schemas used by brazilians internet providers (NET, VIVO, GVT... etc).

## Plugins
This is a community-driven tool. Any user can submit a Pull Request to add a new plugin for a new method of discovering  passwords. You should add a python script to the `plugins/` folder and the plugin must in this format :

**Functions inputs :**
```
ssid = String
mac = String (00:00...)
```

**Functions outputs :**
```
is_vuln(ssid,mac) = Boolean
own(ssid,mac) = Dictionary {'wifi_password':'passwd','admin_login':'admin','admin_password':'passwd'}
```

**Plugins must be in this format :**

 1. pluginName.py on the ./plugins folder.
 2. a `is_vuln` function that returns True or False if the ssid/mac suits your plugin.
 3. a `own` function that returns this dictionary {'wifi_password':'passwd','admin_login':'admin','admin_password':'passwd'}
    if you can't define a variable just return False like {'wifi_password':'passwd','admin_login':False,'admin_password':False}
    'wifi_password' is a must.
 4. a 'brute' variable that specify if your plugin needs some bruteforce 

Follow `plugins/NET_.py` for a example of plugin.
Your plugin will be reviewed before acceptitation.


## Install
`pip install -r requeriments.txt`

## Help
```
DPWO      v0.4
≈≈≈≈≈≈≈≈≈≈≈≈≈≈
usage: dpwo.py [-h] [-i INTERFACE] [-b] [-c] [-a AIRPORT] [-v]

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Network interface. (default: wlp3s0)
  -b, --brute           Enables bruteforce if needed it. (default: False)
  -c, --connect         Autoconnect to the first vulnerable network. (default:
                        False)
  -a AIRPORT, --airport AIRPORT
                        Airport program path. (default: /System/Library/Privat
                        eFrameworks/Apple80211.framework/Versions/A/Resources/
                        airport)
  -v, --verbosity       Increase output verbosity. (default: None)
```

## Blog post (PT-BR) (Outdated)
https://lude.rs/h4ck1ng/NET_2GXXXX_default_password.html
