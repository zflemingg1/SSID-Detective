# Program to discover all ssid's including hidden and the number of the connected clients
# Author: Zach Fleming
#14/08/18

# Import the relevant python libraries
from termcolor import colored
from core import functions
from core import network_functions
import os
import time

class Main_Menu():
	
	interface_selected = False
	mac_address_spoofed = False
	monitor_mode = ''
	interface = ''
	
	# Initialize class
	def __init__(self):
		self.menu()
		
	def additional_banner_info(self):
			
		if self.monitor_mode != '':
			print colored(self.monitor_mode,'red')
				
		if self.mac_address_spoofed == True:
			print colored(self.mac_address_info,'magenta'),
			print colored(" [Spoofed]",'magenta', attrs=['bold'])
		
	def menu(self):
		
		while 1:
			try:
				functions.banner()
				self.additional_banner_info()
				print colored("\nPlease Select 1 Of The Following Options\n", 'yellow',attrs=['bold'])
				print("1. Select Wireless Interface")
				print("2. List Wireless Networks")
				print("3. Exit\n")
				
				choice = functions.user_input_integer(3)
				if choice == 1:
					self.interface = functions.user_select_interface()							# check for wireless interfaces
					functions.system_clear()													# clear the screen
					
					if self.interface is not None:												# if wireless interfaces are found
						self.interface_selected = True											# set interface selected to true
						self.mac_address_info = functions.spoof_mac_address(self.interface)		# spoof mac address
						self.mac_address_spoofed = True											# Set mac address spoofed indicator to true
						functions.enable_monitor_mode(self.interface)							# endable monitor mode
						self.monitor_mode = ("Monitor Mode: " + "[" + self.interface + "]")		# set banner for monitor mode
					else:
						print colored("[!] No available wireless interfaces found ... Exiting Now",'red',attrs=['bold'])
					
				
				elif choice == 2 and self.interface_selected is True:
					functions.system_clear()																# clear screen
					functions.banner()																		# print banner
					self.additional_banner_info()															# print additional banner info

					print colored("\nPlease Select Script Mode:\n", 'yellow',attrs=['bold'])				# ask user which mode the wish to run the script in
					print("1. Aggressive Mode (Actively disconnect clients to determine hidden ssid's)")
					print("2. Passive Mode (Never disconnect clients to determine hidden ssid's)")
					mode = functions.user_input_integer(2)													# pass to function to determine which option user selected and perform basic error checking
					
					functions.system_clear()																# clear screen
					functions.banner()																		# print banner
					self.additional_banner_info()															# print additional banner info
					network_functions.launch(self.interface, mode)
					

					
				elif choice == 3:
					functions.cleanup(self.interface,self.interface_selected,self.mac_address_spoofed)
					
				
				else:
					functions.system_clear()
					print colored ("[!!] An interface must be selected",'yellow',attrs=['bold'])
			
			except KeyboardInterrupt:
				functions.cleanup(self.interface,self.interface_selected,self.mac_address_spoofed)
	
		
		
		
Main_Menu()
		
