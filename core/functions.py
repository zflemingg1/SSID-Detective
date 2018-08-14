from termcolor import colored # needed for colored print
import os
import subprocess
from scapy.all import get_if_addr, get_if_hwaddr, get_working_if



############# System Functions #############

# Print the Banner
def banner():
	print colored("""\


                /(((((                       
                /((((((((((                  
                       (((((/(                
        ###(((# /((((((    (((((              
     ##((####      (((((((   ((((            
   ##(##(       /((    (((((   ((((           
  #(##          /((((((   ((((  ((((          
 #(##               (((((  ((((  (((        
#(##                  ((((  (((( /(((         
#(#          (////(    ((((  (((  (((         
###         (((//(((                          
###          ((((((          ### 	""",'green'),
	print colored("The SSID Detective",'white',attrs=['bold','underline'])
	print colored("""##/                          (## 
#(#                         (###	""",'green'),
	print colored("Designed For Kali Linux",'white')              
	print colored("""##((                        ###               
 ####                      ####		""",'green'),               
	print colored("https://github.com/zflemingg1/SSID-Detective",'white')
	print colored("""  (####                  ####                 
    ######            ######(##               
      ###################   .#(###            
          ####(#######         #######.       
                               ##((#####      
                                ##(((#####    
                                  ##(((#####  
                                    ##((/#####
                                      ##(((###@
""",'green')
	print colored (50 * "-", 'cyan')


# Function to clear the screen
def system_clear():
	os.system("clear")
	return


# Function to choose a number between n-n1 and perform error checking
def user_input_integer(num_range):
	
	while True:
    		try:  
				userInput = int(raw_input('\nPlease Enter Choice [' + repr(1) + '-' + repr(num_range) + ']: '))       
    		except ValueError:
       			print("Not an integer! Try again.")
       			continue
       		except KeyboardInterrupt:
				raise
    		else:
       			if(userInput < 1 or userInput > num_range ):
				print("Error Please Select A Valid Number")
			else:
				return userInput 
       				break 


# Function to select wireless nic
def user_select_interface():

	system_clear()
	interfaces = get_list_of_interfaces()
	
	## Add Ip Addresses to list for number of interfaces ##
	interface_list = get_ip_of_interface(interfaces)

	i = 0
	count = 0
	banner()
	print colored ("Available Interfaces (Interface:IP Address)", 'yellow')
	for interface in interface_list:
		count +=1
		print(repr(count) + "." + ''.join([' : '.join([k,v]) for k, v in interface_list.items()]))
		i+=1

		## User Selects Interface ##
		choice = user_input_integer(count)
		selected_interface = interfaces[choice - 1]

		return selected_interface
	system_clear()
	interfaces = get_list_of_interfaces()
	
	## Add Ip Addresses to list for number of interfaces ##
	interface_list = get_ip_of_interface(interfaces)

	i = 0
	count = 0
	banner()
	print colored ("Available Interfaces (Interface:IP Address)", 'yellow')
	for interface in interface_list:
		count +=1
		print(repr(count) + "." + ''.join([' : '.join([k,v]) for k, v in interface_list.items()]))
		i+=1

		## User Selects Interface ##
		choice = user_input_integer(count)
		selected_interface = interfaces[choice - 1]

		return selected_interface


# Function to get a list of available interfaces
def get_list_of_interfaces():
	# Add Wireless Interfaces to list
	FNULL = open(os.devnull, 'w')
	proc = subprocess.Popen(['iwconfig'],stdout=subprocess.PIPE, stderr=FNULL)
	iface = ''
	interfaces = []
	
	# For loop o iterate over interfaces and add wireless ones to list
	for line in proc.communicate()[0].split('\n'):
		
		if line.startswith((' ', '\t')) or len(line) ==0:  # Ignore if line starts with a space or is of 0 length
			continue
		else:
			iface = line[:line.find(' ')]  # is the interface
		
		interfaces.append(iface) # Add interface to list
		
	return interfaces


# Function to get the ip address of the available network interfaces
def get_ip_of_interface(interfaces_list):
	interfaces = {}
	for iface in interfaces_list:
		ip_address = get_if_addr(iface)
		if (ip_address == "0.0.0.0") or (ip_address is None):
			interfaces[iface] = "None"
		else:
			interfaces[iface] = ip_address
			
	return interfaces


# Function to spoof the mac address
def spoof_mac_address(interface):
	banner()
	print colored ("[*] Spoofing Mac Address For " + interface,'yellow')
	os.system("ifconfig " + interface + " down")
	mac_address_info = os.popen("macchanger -r " + interface).read()
	mac_address_info = mac_address_info[:-1]
	os.system("ifconfig " + interface + " up")
	print colored ("[*] Spoofing Mac Address For " + interface + " [OK]",'green')
	return mac_address_info 


# Function to enable monitor mode
def enable_monitor_mode(interface):
	print colored("\n[*] Enabling Monitor Mode On: " + interface,'yellow')
	try:
		os.system("ifconfig " + interface + " down")
		os.system("iwconfig " + interface + " mode monitor")
		os.system("ifconfig " + interface + " up")
		print colored("[*] Enabling Monitor Mode On: " + interface + " [OK]",'green')
		system_clear()
	except Exception as e:
		print("[!!] Error unable to to set up monitoring mode on interface: " + interface)
		print str(e)


def cleanup(interface,interface_status,mac_address_spoofed):
	
	if interface_status == False:
		print colored("\nUser Terminated Program\n",'red',attrs=['bold'])
		exit(0)
	else:
		system_clear()
		banner()
		print colored("\n[*] Terminating Program...\n",'red',attrs=['bold'])
		# Restore Mac Address
		if mac_address_spoofed == True:
			print colored("[*] Restoring Mac Address For " + interface,'yellow',attrs=['bold'])
			os.system("ifconfig " + interface + " down")
			os.system("macchanger -p " + interface)
			os.system("ifconfig " + interface + " up")
			print colored("[*] Restoring Mac Address For " + interface + " [OK]\n",'green',attrs=['bold'])
		
		# Restore Managed Mode From Monitor
		if interface_status == True:
			print colored("[*] Disabling Monitor Mode & Restoring Managed Mode For " + interface,'yellow',attrs=['bold'])
			os.system("ifconfig " + interface + " down")
			os.system("iwconfig " + interface + " mode managed")
			os.system("ifconfig " + interface + " up")
			print colored("[*] Disabling Monitor Mode & Restoring Managed Mode For " + interface + " [OK]\n",'green',attrs=['bold'])
			
		exit(0)
	
