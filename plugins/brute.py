'''
ssid = string
mac = 00:00...
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
	return False	

def own(ssid,mac) :
	brute_force = []

	password = mac.replace(":","").upper()[4:]

	brute_force.append({'ssid':ssid,'mac':mac,'wifi_password':password,'admin_login':'','admin_password':''})

	password = mac.replace(":","").upper()[2:]

	brute_force.append({'ssid':ssid,'mac':mac,'wifi_password':password,'admin_login':'','admin_password':''})

	password = mac.replace(":","").lower()[2:]

	brute_force.append({'ssid':ssid,'mac':mac,'wifi_password':password,'admin_login':'','admin_password':''})

	password = mac.replace(":","").lower()[4:]

	brute_force.append({'ssid':ssid,'mac':mac,'wifi_password':password,'admin_login':'','admin_password':''})

	return brute_force
