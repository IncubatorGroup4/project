#!/usr/bin/env python

#Importing all the neccessary modules
import sys
import re
import os
import subprocess
import time
import threading
import socket

#regex pattern for ip address search
ip_addr_pattern = re.compile("^(((25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\/(3[0-2]|2\d|1\d|\d))(\s+\#.*|\s*)?$")

try:
	from colorama import init, deinit, Fore, Style
except ImportError:
	print "\n* Module colorama needs to be installed on your system."
	print "* Download it from: https://pypi.python.org/pypi/colorama\n"
	sys.exit()

#Initializing colorama
init()

try:
	import requests
except ImportError:
	print Fore.RED + Style.BRIGHT + "* Module" + Fore.YELLOW + Style.BRIGHT + " requests" + Fore.RED + Style.BRIGHT + " needs to be installed on your system."
	print "* Download it from: " + Fore.GREEN + Style.BRIGHT + "https://pypi.python.org/pypi/requests\n" + Fore.WHITE + Style.BRIGHT + "\n"
	sys.exit()

try:
	import netifaces
except ImportError:
	print Fore.RED + Style.BRIGHT + "* Module" + Fore.YELLOW + Style.BRIGHT + " netifaces" + Fore.RED + Style.BRIGHT + " needs to be installed on your system."
	print "* Download it from: " + Fore.GREEN + Style.BRIGHT + "https://pypi.python.org/pypi/netifaces\n" + Fore.WHITE + Style.BRIGHT + "\n"
	sys.exit()

try:
	import ipaddress
except ImportError:
	print Fore.RED + Style.BRIGHT + "* Module" + Fore.YELLOW + Style.BRIGHT + " ipaddress" + Fore.RED + Style.BRIGHT + " needs to be installed on your system."
	print "* Download it from: " + Fore.GREEN + Style.BRIGHT + "https://pypi.python.org/pypi/ipaddress\n" + Fore.WHITE + Style.BRIGHT + "\n"
	sys.exit()

try:
	from pprint import pprint
except ImportError:
	print Fore.RED + Style.BRIGHT + "* Module" + Fore.YELLOW + Style.BRIGHT + " pprint" + Fore.RED + Style.BRIGHT + " needs to be installed on your system."
	print "* Download it from: " + Fore.GREEN + Style.BRIGHT + "https://pypi.python.org/pypi/pprint" + Fore.WHITE + Style.BRIGHT + "\n"
	sys.exit()

try:
	import textfsm
except ImportError:
	print Fore.RED + Style.BRIGHT + "* Module" + Fore.YELLOW + Style.BRIGHT + " textfsm" + Fore.RED + Style.BRIGHT + " needs to be installed on your system."
	print "* Download it from: " + Fore.GREEN + Style.BRIGHT + "https://pypi.python.org/pypi/textfsm" + Fore.WHITE + Style.BRIGHT + "\n"
	sys.exit()

try:
	import paramiko
except ImportError:
	print Fore.RED + Style.BRIGHT + "* Module" + Fore.YELLOW + Style.BRIGHT + " paramiko" + Fore.RED + Style.BRIGHT + " needs to be installed on your system."
	print "* Download it from: " + Fore.GREEN + Style.BRIGHT + "https://pypi.python.org/pypi/paramiko" + Fore.WHITE + Style.BRIGHT + "\n"
	sys.exit()

try:
	import matplotlib.pyplot as matp
except ImportError:
	print Fore.RED + Style.BRIGHT + "* Module" + Fore.YELLOW + Style.BRIGHT + " matplotlib" + Fore.RED + Style.BRIGHT + " needs to be installed on your system."
	print "* Download it from: " + Fore.GREEN + Style.BRIGHT + "https://pypi.python.org/pypi/matplotlib" + Fore.WHITE + Style.BRIGHT + "\n"
	sys.exit()

try:
	import networkx as nx
except ImportError:
	print Fore.RED + Style.BRIGHT + "* Module" + Fore.YELLOW + Style.BRIGHT + " networkx" + Fore.RED + Style.BRIGHT + " needs to be installed on your system."
	print "* Download it from: " + Fore.GREEN + Style.BRIGHT + "https://pypi.python.org/pypi/networkx" + Fore.WHITE + Style.BRIGHT + "\n"
	sys.exit()

#Create all the necessary variables

#List of available ips
available_ips = []

#List (of dictionaries) of management information for each device
dev_manage_info = []

#List with cdp information for each device; "show cdp neighbors detail" command
dev_cdp_list = []

#List with general information for each device (list of dictionaries); "show version" command
dev_ver_info = []


#DICTIONARIES
#Module information for each device (dictionary(key = hostname) of lists of dictionaries(each module))
dev_module_info = {}

#For topology generation
neighborship_dict = {}

#Interface information for each device (dict(key = hostname) of lists of dictionaries(each interface))
dev_iface_info = {}

eox_info = {}

eox_soft = {}


def ip_is_valid(file):
	"""Checks if all ip addresses in the file are valid. 
	Returns tuple of 2 elements:
	1) List of valid ip ranges;
	2) List of appropriate subnet masks."""

	ip_list = []
	mask_list = []
	check = False

	while True:
		try:
			with open(file) as myfile:
				myfile.seek(0)

				#Check if the file is empty
				if not myfile.read(1):
					print Fore.RED + Style.BRIGHT + "* File " + Fore.YELLOW + file + Fore.RED + Style.BRIGHT + " is empty!"
					print "* Please verify your file!"
					sys.exit()

				myfile.seek(0)
				data = myfile.readline()

				range_list = data.split(",")
				
				#Remove empty spaces for each range
				range_list = [item.strip() for item in range_list]
				
				for line in range_list:
					if ip_addr_pattern.search(line) != None:
							entry = ip_addr_pattern.search(line).group(1)
							ip = entry.split("/")[0]
							mask = entry.split("/")[1]
							if ip == get_net_addr(ip, mask):
								ip_list.append(ip)
								mask_list.append(mask)
							else:
								print Fore.RED + Style.BRIGHT + "\n* The file should contain only ip network addresses(ranges), not a concrete ip addresses"
								print "\n* Please verify your file: " + Fore.YELLOW + Style.BRIGHT + file
								sys.exit()
					else:
						print Fore.RED + Style.BRIGHT + "\n* The following line is unacceptable"
						print Fore.YELLOW + Style.BRIGHT + "'" + line + "'"
						print Fore.RED + Style.BRIGHT + "\n* Please verify your file: " + Fore.YELLOW + Style.BRIGHT + file
						sys.exit()

		except IOError as err:
			print Fore.RED + Style.BRIGHT + str(err)
			print Fore.RED + Style.BRIGHT + "\n* File " + Fore.YELLOW + Style.BRIGHT + file + Fore.RED + Style.BRIGHT + " does not exist! Please check and try again!\n"
			print Fore.WHITE + Style.BRIGHT
			sys.exit()

		#Checking octets
		for each_ip in ip_list:
			a = each_ip.split(".")
			if (len(a) == 4) and (1 <= int(a[0]) <= 223) and (int(a[0]) != 127) and (int(a[0]) != 169 or int(a[1]) != 254) and (0 <= int(a[1]) <= 255 and 0 <= int(a[2]) <= 255 and 0 <= int(a[3]) <= 255):
				check = True
				continue
			else:
				print Fore.RED + Style.BRIGHT + "\n* This ip address: " + Fore.YELLOW + Style.BRIGHT + each_ip + Fore.RED + Style.BRIGHT + " is unacceptable!"
				print "\n* Please verify your file!"
				check = False
				break

		#Evaluate the check flag
		if check == True:
			print Fore.GREEN + Style.BRIGHT + "\n* All ip addresses in the file " + Fore.YELLOW + Style.BRIGHT + file + Fore.GREEN + Style.BRIGHT + " are verified and valid!\n"
			break
		elif check == False:
			sys.exit()

	return ip_list, mask_list

def pass_is_valid(file):
	"""Check if the file with passwords is not empty and exists. Return a list of passwords from the file."""

	pass_list = []

	while True:
		if os.path.isfile(file) == True:
			with open(file) as myfile:
				myfile.seek(0)

				if not myfile.read(1):
					print Fore.RED + Style.BRIGHT + "* File " + Fore.YELLOW + file + Fore.RED + Style.BRIGHT + " is empty!"
					print "* Please verify your file!"
					sys.exit()

				myfile.seek(0)
				for line in myfile:
					if line.rstrip("\n") in pass_list:
						continue
					pass_list.append(line.rstrip("\n"))
			break
		else:
			print Fore.RED + Style.BRIGHT + "\n* File " + Fore.YELLOW + Style.BRIGHT + file + Fore.RED + Style.BRIGHT + " does not exist! Please check and try again!\n"
			print Fore.WHITE + Style.BRIGHT
			sys.exit()

	print Fore.GREEN + Style.BRIGHT + "* File with passwords exists: " + Fore.YELLOW + Style.BRIGHT + file
	return pass_list

def get_net_addr(ip, dec_mask):
	"""Calculates network address for given ip address and subnet mask. 
	get_net_addr(ip, dec_mask) --> net_addr."""

	#Algorithm for subnet identification, based on IP and Subnet Mask

	#Convert mask to binary string
	netmask = "1" * int(dec_mask) + "0" * (32 - int(dec_mask))

	no_of_zeros = netmask.count("0")
	no_of_ones = 32 - no_of_zeros
	no_of_hosts = abs(2 ** no_of_zeros - 2)

	#Convert IP to binary string
	ip_octets_padded = []
	ip_octets_decimal = ip.split(".")

	for octet_index in range(0, len(ip_octets_decimal)):
		bin_octet = bin(int(ip_octets_decimal[octet_index])).split("b")[1]

		if len(bin_octet)<8:
			bin_octet_padded = bin_octet.zfill(8)
			ip_octets_padded.append(bin_octet_padded)
		else:
			ip_octets_padded.append(bin_octet)

	#Join binary octets into one binary string
	binary_ip = "".join(ip_octets_padded)
	#print binary_ip

	#Add zeros to the end (calculate network address in binary format)
	net_addr_bin = binary_ip[:(no_of_ones)] + "0" * no_of_zeros
	#print net_addr_bin

	#Convert net. address to a list of binary octets
	net_addr_bin_list = []
	for i in range(0, 32, 8):
		oc = net_addr_bin[i:i+8]
		net_addr_bin_list.append(oc)

	#print net_addr_bin_list

	#Convert binary octets in the list to decimal format
	net_addr_dec_list = []
	for i in net_addr_bin_list:
		oc_dec = int(i, 2)
		net_addr_dec_list.append(str(oc_dec))

	#Get a resulting string (network ip address in decimal format)
	net_addr_dec = ".".join(net_addr_dec_list)
	#print net_addr_dec

	return net_addr_dec

def get_all_net_hosts(ip, dec_mask):
	"""Calculates all possible host ip addresses for a given network address and subnet mask. Return a list of addresses."""

	network = ipaddress.ip_network(u"%s/%s" % (ip, dec_mask))

	net_hosts = [str(host) for host in network.hosts()]

	return net_hosts

def ping(ip):
	"""Ping ip address. If ping is successful add the ip address to the available_ips list."""

	if sys.platform.startswith("linux") or sys.platform.startswith("darwin"):
		ping_reply = subprocess.call(["ping", "-c", "2", "-w", "2", "-q", "-n", ip], stdout = subprocess.PIPE)
	elif sys.platform.startswith("win"):
		ping_reply = subprocess.call(["ping", "-n", "2", "-w", "2", ip], stdout = subprocess.PIPE)

	if ping_reply == 0:
		available_ips.append(ip)
	elif ping_reply == 2:
		pass
		#print Fore.RED + Style.BRIGHT + "\n* No response from the device --> " + Fore.YELLOW + Style.BRIGHT + ip
	else:
		pass
		#print Fore.RED + Style.BRIGHT + "\n* Ping to the following device has failed --> " + Fore.YELLOW + Style.BRIGHT + ip

def create_ping_threads(ip_list):
	"""Creates threads for each ip address in ip_list."""

	threads = []
	for ip in ip_list:
		th = threading.Thread(target = ping, args = (ip,))
		th.start()
		threads.append(th)

	for th in threads:
		th.join()

def chech_loc_ifaces():
	"""Find and remove local interfaces from the available_ips list."""

	iface_list = netifaces.interfaces()

	for iface in iface_list:
	 	try:
	 		ip = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]["addr"]
	 		if ip in available_ips:
	 			#print "\n I'll remove the following interface from the list because it's mine interface:) --> " + Fore.YELLOW + Style.BRIGHT + iface
	 			#print Fore.WHITE + Style.BRIGHT + "\n"
	 			available_ips.remove(ip)
	 	except KeyError:
	 		#print "Error with interface: " + Fore.YELLOW + Style.BRIGHT + iface
	 		#print Fore.WHITE + Style.BRIGHT + "\n"
	 		continue

def open_ssh_conn(ip, pswd_list):
	"""Create SSH connection to the device with a given ip address. Second argument is a password list.
	Returns True if successfully create paramiko.SSHClient() object or False if not"""

	ssh_check = False

	username = "admin"

	#Dictionary which contain management information (username, password and management ip) for each device
	dev_manage = {}

	for pswd in pswd_list:
		try:
			ssh_client = paramiko.SSHClient()
			ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
			a = ssh_client.connect(ip, username = username, password = pswd)
			if a == None:
				ssh_check = True
				break
		except paramiko.AuthenticationException:
			ssh_client.close()
			#print Fore.RED + Style.BRIGHT + "\n* Invalid SSH password --> " + Fore.YELLOW + Style.BRIGHT + pswd
			#print Fore.RED + Style.BRIGHT + "\n* Please check the file."
			#print Fore.WHITE + Style.BRIGHT + "\n"
			continue
		#except paramiko.ssh_exception.NoValidConnectionsError:
			#ssh_check = False
			#print Fore.RED + Style.BRIGHT + "\n Too many vty connections to device --> " + ip
			#print Fore.WHITE + Style.BRIGHT + "\n"
			#break
		except socket.error as err:
			ssh_check = False
			print Fore.RED + Style.BRIGHT + "*\n Error: " + str(err)
			print "* Check if the RSA key is configured on the device!"
			break

	#Evaluate ssh_check flag
	if ssh_check == True:
		#Create a shell to execute commands
		conn =  ssh_client.invoke_shell()

		conn.send("terminal length 0\n")

		conn.send("show ip interface brief\n")
		time.sleep(1)

		output = conn.recv(1000)

		dev_manage["username"] = username
		dev_manage["password"] = pswd
		dev_manage["manage_ip"] = ip
		dev_manage["ssh_client"] = ssh_client
		dev_manage["shell"] = conn

		#Add dev_manage dict to a list
		dev_manage_info.append(dev_manage)

		#Create a template object for "show ip int brief" command
		sh_ip_int_b = textfsm.TextFSM(open(r"./templates/sh_ip_int_b.textfsm"))
		sh_ip_int_b_res = sh_ip_int_b.ParseText(output)

		#Find out unqueried ip addresses (remove queried ip addresses from the available_ips list)
		for line in sh_ip_int_b_res:
			nbr_ip = line[1]
			if nbr_ip in available_ips:
				available_ips.remove(nbr_ip)
	else:
		print "\n* Password is not found for a device with ip  " + Fore.YELLOW + Style.BRIGHT + ip
		print Fore.WHITE + Style.BRIGHT + "\n"
		available_ips.remove(ip)

def gather_info(ssh_client, conn):
	"""Gather all the neccessary information for a device. Accepts paramiko.SSHClient() object"""

	conn.send("show running-config | include hostname\n")
	time.sleep(1)

	############################

	conn.send("show diag\n")
	time.sleep(1)

	conn.send("show cdp neighbors detail\n")
	time.sleep(1)

	conn.send("show interfaces\n")
	time.sleep(2)

	conn.send("show version\n")
	time.sleep(1)

	############################

	output = conn.recv(65535)

	#Find device hostname
	dev_hostname = re.search(r"hostname (\S+)\s*", output)
	if dev_hostname != None:
		hostname = dev_hostname.group(1)
		#Add to a dictionary hostname
		for dev in dev_manage_info:
			if dev["ssh_client"] == ssh_client:
				dev["hostname"] = hostname

	#Create a template object for "show interfaces" command
	sh_ifaces = textfsm.TextFSM(open(r"./templates/sh_interfaces.textfsm"))
	sh_ifaces_res = sh_ifaces.ParseText(output)

	#Template list for iface_dict dictionary
	ifaces_temp = ["iface", "phy_st", "prot_st", "description", "ip_addr", "mtu", "bandwidth"]

	#Create a list to contain all interfaces for a device
	ifaces = []
	for value in sh_ifaces_res:
		#Create dictionary for each interface on a device
		iface_dict = {key:value[index] for index, key in enumerate(ifaces_temp)}
		ifaces.append(iface_dict)

	#Add list with interfaces to a dictionary
	dev_iface_info[hostname] = ifaces

	#Create a template object for "show diag" command(search for adapter modules)
	sh_diag_ad = textfsm.TextFSM(open(r"./templates/sh_diag_slots.textfsm"))
	sh_diag_ad_res = sh_diag_ad.ParseText(output)

	#Template list for ad_modules dictionary
	ad_mod_temp = ["slot_no", "module_name", "port_no", "status", "insert_time", "serial_no", "hard_rev", "pid"]

	#Create list to contain all adapter modules for a device
	adapter_modules = []
	for value in sh_diag_ad_res:
		#Create a dictionary for each adapter module on a device
		ad_modules = {key:value[index] for index, key in enumerate(ad_mod_temp)}
		adapter_modules.append(ad_modules)


	#Create a template object for "show diag" command(search for wic modules)
	sh_diag_wic = textfsm.TextFSM(open(r"./templates/sh_diag_wics.textfsm"))
	sh_diag_wic_res = sh_diag_wic.ParseText(output)

	#Template list for w_modules dictionary
	wic_mod_temp = ["slot_no", "module_name", "hard_rev", "serial_no", "pid"]

	#Create list to contain all WIC modules for a device
	wic_modules = []
	for value in sh_diag_wic_res:
		#Create dictionary for each WIC module on a device
		w_modules = {key:value[index] for index, key in enumerate(wic_mod_temp)}
		wic_modules.append(w_modules)

	#Add adapter and WIC modules for a device to the dictionary
	dev_module_info[hostname] = [adapter_modules, wic_modules]

	#Collecting cdp information
	#Create a template object for "show cdp neighbors detail" command
	sh_cdp_nbr_d = textfsm.TextFSM(open(r"./templates/sh_cdp_nbr_d.textfsm"))
	sh_cdp_nbr_d_res = sh_cdp_nbr_d.ParseText(output)

	#Template list for cdp_nbr doctionary
	cdp_nbr_temp = ["nbr_id", "nbr_domain", "nbr_ip", "host_iface", "nbr_iface"]

	for value in sh_cdp_nbr_d_res:
		#Create dictionary to contain neighbor information for a device
		cdp_nbr = {key:value[index] for index, key in enumerate(cdp_nbr_temp)}
		cdp_nbr["host_id"] = hostname

		#Add cdp info for a device to a list
		dev_cdp_list.append(cdp_nbr)


	#Template list for sh_ver_dict doctionary
	sh_ver_temp = ["sys_type", "hard_platform", "soft_name", "soft_ver", "hostname", "uptime",
					"image", "proc_type", "proc_freq", "ram_mem", "shared_mem", "nvram", "conf_reg"]

	#Create a template object for "show version" command
	sh_ver = textfsm.TextFSM(open(r"./templates/sh_ver.textfsm"))
	sh_ver_res = sh_ver.ParseText(output)

	#Create a dictionary to contain general info for a device
	sh_ver_dict = {key:sh_ver_res[0][index] for index, key in enumerate(sh_ver_temp)}

	#Search for a device uptime from the output
	uptime_value_list = sh_ver_dict["uptime"].split(", ")

	#Getting the device uptime in seconds
	y_sec = 0
	w_sec = 0
	d_sec = 0
	h_sec = 0
	m_sec = 0

	for i in uptime_value_list:
		if "year" in i:
			y_sec = int(i.split(" ")[0]) * 31449600
		elif "week" in i:
			w_sec = int(i.split(" ")[0]) * 604800
		elif "day" in i:
			d_sec = int(i.split(" ")[0]) * 86400
		elif "hour" in i:
			h_sec = int(i.split(" ")[0]) * 3600
		elif "minute" in i:
			m_sec = int(i.split(" ")[0]) * 60

	uptime = y_sec + w_sec + d_sec + h_sec + m_sec

	#Add uptime in seconds to the dictionary
	sh_ver_dict["uptime"] = str(uptime)

	#Add dict to the list of general information for each device
	dev_ver_info.append(sh_ver_dict)

	#Create a dictionary for topology generation
	for each_dict in dev_cdp_list:
		edge_tuple = (each_dict["host_id"], each_dict["nbr_id"])
		neighborship_dict[edge_tuple] = (each_dict["nbr_iface"], each_dict["nbr_ip"])

	#Close SSH session
	ssh_client.close()

def create_ssh_threads(ssh_list):
	"""Creates threads for each ssh_client in ssh_list."""

	threads = []
	for dev in ssh_list:
		th = threading.Thread(target = gather_info, args = (dev["ssh_client"], dev["shell"]))
		th.start()
		threads.append(th)
		time.sleep(2)

	for th in threads:
		th.join()


def write_cred_csv():
	"""Write credentials and management ips for each device to the file results/dev_credentials.csv"""

	filename = r"./results/dev_credentials.csv"

	if not os.path.exists(os.path.dirname(filename)):
		try:
			os.makedirs(os.path.dirname(filename))
		except OSError as err:
			print Fore.RED + Style.BRIGHT + "\n* Error: %s" % str(err)
			sys.exit()


	output_file = open(filename, "w")

	print >>output_file, "Device;Username;Password;Management IP"

	for each_dict in dev_manage_info:
		print >>output_file, "%s;%s;%s;%s" % (each_dict["hostname"], each_dict["username"], each_dict["password"], each_dict["manage_ip"])

	output_file.close()

	print Fore.BLUE + Style.BRIGHT + "* Credentials for each device is saved to " + Fore.YELLOW + filename + Fore.BLUE + Style.BRIGHT + " file!"
	print "* You can open it using Microsoft Excel"
	print Fore.WHITE + Style.BRIGHT + "\n"

def write_ver_info():
	"""Write general information for each device to the file results/dev_general.txt"""

	filename = r"./results/dev_general.txt"

	if not os.path.exists(os.path.dirname(filename)):
		try:
			os.makedirs(os.path.dirname(filename))
		except OSError as err:
			print Fore.RED + Style.BRIGHT + "\n* Error: %s" % str(err)
			sys.exit()

	output_file = open(filename, "w")

	for host in dev_ver_info:
		print >>output_file, "############################### General information for the device: %s ###############################" % host["hostname"]
		print >>output_file, "System type: %s" % host["sys_type"]
		print >>output_file, "Hardware platform: %s" % host["hard_platform"]
		print >>output_file, "Software name: %s" % host["soft_name"]
		print >>output_file, "Software version: %s" % host["soft_ver"]
		print >>output_file, "Image file: %s" % host["image"]
		print >>output_file, "Processor type: %s" % host["proc_type"]
		print >>output_file, "Processor frequency: %s MHz" % host["proc_freq"]
		print >>output_file, "Main (RAM) memory: %s Kbytes" % host["ram_mem"]
		print >>output_file, "Shared memory: %s Kbytes" % host["shared_mem"]
		print >>output_file, "NVRAM: %s Kbytes" % host["nvram"]
		print >>output_file, "Configuration register: %s" % host["conf_reg"]
		#print >>output_file, "\nEoL information for the software release: %s" % host["soft_ver"]
		#print >>output_file, "\tEnd of Sale Date: %s" % eox_soft[host["soft_ver"]]["EndOfSaleDate"]
		#print >>output_file, "\tLast day of Support: %s" % eox_soft[host["soft_ver"]]["LastDateOfSupport"]
		#print >>output_file, "\tEnd of S/W Maintainence Releases Date: %s\n" % eox_soft[host["soft_ver"]]["EndOfSWMaintenanceReleases"]

	output_file.close()
	print Fore.BLUE + Style.BRIGHT + "\n* General information for each device is saved to " + Fore.YELLOW + filename
	print Fore.WHITE + Style.BRIGHT + "\n"

def write_iface_info():
	"""Write interface information for each device to the file results/dev_interfaces.txt"""

	filename = r"./results/dev_interfaces.txt"

	if not os.path.exists(os.path.dirname(filename)):
		try:
			os.makedirs(os.path.dirname(filename))
		except OSError as err:
			print Fore.RED + Style.BRIGHT + "\n* Error: %s" % str(err)
			sys.exit()


	output_file = open(filename, "w")

	for host in dev_iface_info.keys():
		print >>output_file, "############################### Interface information for the device: %s ###############################" % host

		#["iface", "phy_st", "prot_st", "description", "ip_addr", "mtu", "bandwidth"]
		for each_dict in dev_iface_info[host]:
			print >>output_file, "----- %s -----" % each_dict["iface"]
			if each_dict["ip_addr"] == "":
				print >>output_file, "\tIP address: unassigned"
			else:
				print >>output_file, "\tIP address: %s" % each_dict["ip_addr"]
			print >>output_file, "\tOperational state: %s" % each_dict["phy_st"]
			print >>output_file, "\tProtocol state: %s" % each_dict["prot_st"]
			print >>output_file, "\tDescription: %s" % each_dict["description"]
			print >>output_file, "\tMTU: %s bytes" % each_dict["mtu"]
			print >>output_file, "\tBandwidth: %s Kbit/sec" % each_dict["bandwidth"]

	output_file.close()
	print Fore.BLUE + Style.BRIGHT + "\n* Interface information for each device is saved to " + Fore.YELLOW + filename
	print Fore.WHITE + Style.BRIGHT + "\n"

def write_module_info():
	"""Write information about modules for each device to the file results/dev_modules.txt"""

	filename = r"./results/dev_modules.txt"

	if not os.path.exists(os.path.dirname(filename)):
		try:
			os.makedirs(os.path.dirname(filename))
		except OSError as err:
			print Fore.RED + Style.BRIGHT + "\n* Error: %s" % str(err)
			sys.exit()

	output_file = open(filename, "w")

	for host in dev_module_info.keys():
		print >>output_file, "############################### Module information for the device: %s ###############################\n" % host

		print >>output_file, "******************** ADAPTERS ********************"
		for each_dict in dev_module_info[host][0]:
			print >>output_file, "----- Slot %s -----" % each_dict["slot_no"]
			print >>output_file, "\tModule: %s" % each_dict["module_name"]
			print >>output_file, "\tStatus: %s" % each_dict["status"]
			print >>output_file, "\tPort adapter insertion time: %s ago" % each_dict["insert_time"]
			print >>output_file, "\tSerial number: %s" % each_dict["serial_no"]
			print >>output_file, "\tHardware revision: %s" % each_dict["hard_rev"]
			print >>output_file, "\tPID: %s" % each_dict["pid"]

			if eox_info[each_dict["pid"]]["EndOfSaleDate"] == u"" or eox_info[each_dict["pid"]]["EndOfSaleDate"] == u" ":
				print >>output_file, "\tEnd of Sale Date: No information available"
			else:
				print >>output_file, "\tEnd of Sale Date: %s (YYYY-MM-DD)" % eox_info[each_dict["pid"]]["EndOfSaleDate"]

			if eox_info[each_dict["pid"]]["EndOfSWMaintenanceReleases"] == u"" or eox_info[each_dict["pid"]]["EndOfSWMaintenanceReleases"] == u" ":
				print >>output_file, "\tEnd of SW Maintenance Releases: No information available"
			else:
				print >>output_file, "\tEnd of SW Maintenance Releases: %s (YYYY-MM-DD)" % eox_info[each_dict["pid"]]["EndOfSWMaintenanceReleases"]

			if eox_info[each_dict["pid"]]["LastDateOfSupport"] == u"" or eox_info[each_dict["pid"]]["LastDateOfSupport"] == u" ":
				print >>output_file, "\tLast Date of Support: No information available\n"
			else:
				print >>output_file, "\tLast Date of Support: %s (YYYY-MM-DD)\n" % eox_info[each_dict["pid"]]["LastDateOfSupport"]

		print >>output_file, "******************** WICS ********************"
		for each_dict in dev_module_info[host][1]:
			print >>output_file, "----- Slot %s -----" % each_dict["slot_no"]
			print >>output_file, "\tModule: Serial %s" % each_dict["module_name"]
			print >>output_file, "\tStatus: analyzed"
			print >>output_file, "\tSerial number: %s" % each_dict["serial_no"]
			print >>output_file, "\tHardware revision: %s" % each_dict["hard_rev"]
			print >>output_file, "\tPID: %s" % each_dict["pid"]

			if eox_info[each_dict["serial_no"]]["EndOfSaleDate"] == u"" or eox_info[each_dict["serial_no"]]["EndOfSaleDate"] == u" ":
				print >>output_file, "\tEnd of Sale Date: No information available"
			else:
				print >>output_file, "\tEnd of Sale Date: %s (YYYY-MM-DD)" % eox_info[each_dict["serial_no"]]["EndOfSaleDate"]

			if eox_info[each_dict["serial_no"]]["EndOfSWMaintenanceReleases"] == u"" or eox_info[each_dict["serial_no"]]["EndOfSWMaintenanceReleases"] == u" ":
				print >>output_file, "\tEnd of SW Maintenance Releases: No information available"
			else:
				print >>output_file, "\tEnd of SW Maintenance Releases: %s (YYYY-MM-DD)" % eox_info[each_dict["serial_no"]]["EndOfSWMaintenanceReleases"]

			if eox_info[each_dict["serial_no"]]["LastDateOfSupport"] == u"" or eox_info[each_dict["serial_no"]]["LastDateOfSupport"] == u" ":
				print >>output_file, "\tLast Date of Support: No information available\n"
			else:
				print >>output_file, "\tLast Date of Support: %s (YYYY-MM-DD)\n" % eox_info[each_dict["serial_no"]]["LastDateOfSupport"]

	output_file.close()
	print Fore.BLUE + Style.BRIGHT + "\n* Module information for each device is saved to " + Fore.YELLOW + filename
	print Fore.WHITE + Style.BRIGHT + "\n"

def draw_topology():
	"""Draw network topology"""

	print Fore.CYAN + Style.BRIGHT + "\n* Generating network topology..."
	print Fore.CYAN + Style.BRIGHT + "\n* You can save it as a .png file\n" + Fore.BLUE + Style.BRIGHT

	#Drawing the topology using the list of neighborships
	G = nx.Graph()
	G.add_edges_from(neighborship_dict.keys())
	pos = nx.spring_layout(G, k = 0.5, iterations = 70)
	nx.draw_networkx_labels(G, pos, font_size = 9, font_family = "sans-serif", font_weight = "bold")
	nx.draw_networkx_edges(G, pos, width = 4, alpha = 0.4, edge_color = 'black')
	nx.draw_networkx_edge_labels(G, pos, neighborship_dict, label_pos = 0.3, font_size = 6)
	nx.draw(G, pos, node_size = 700, with_labels = True)
	matp.show()


#Coffee cup
#P.S Just a funny stuff
coffee = r"""                                /\
                          /\   / /
                         / /   \ \
                         \ \    \ \
                          \ \    \ \
                          / /    / /
                         / /     \/
                         \/
                   ***********************
                ***                       ***
              **                             **
              ****                         ***** ******
              ***********************************      ** 
              *********************************        **
               *******************************        **
                *****************************     ****
                 *********************************
                  **************************
                   ***********************
                      ***************** 
                         ***********
		"""



if __name__ == "__main__":
	try:
		#Check the number of arguments
		if len(sys.argv) == 3:
			range_file = sys.argv[1]
			pass_file = sys.argv[2]
		else:
			print sys.argv
			print "\n* Incorrect number of arguments!"
			sys.exit()

		#Get and verify all ip addresses from the file
		ips, masks = ip_is_valid(range_file)
		#print ips
		#print masks

		#Get all passwords from the file
		pass_list = pass_is_valid(pass_file)

		#Create list to contain all host ip addresses for a specific network address
		devices = []

		for index, ip in enumerate(ips):
			#Generate all possible host network addresses for a given network address(ip) and subnet mask
			hosts = get_all_net_hosts(ip, masks[index])

			#Create dictionary for each network address
			tmp_dict = {"net_addr": ip, "hosts": hosts}

			#Add dict to a list
			devices.append(tmp_dict)

		#Ping each host ip address in the devices list 
		print Fore.GREEN + Style.BRIGHT + "\n* Cheking ip connectivity....Please wait....\n"

		for i in devices:	
			create_ping_threads(i["hosts"])

		#Remove local interface from the available_ips list
		chech_loc_ifaces()

		print "\n Available ips: "
		pprint(available_ips)

		print Fore.GREEN + Style.BRIGHT + "\n* IP addresses are found!"
		print "* I will create SSH connections to devices and gather all the necessary information for you!"
		print "* Please wait....It might take up to 2 minutes"
		print "* Time for coffee:)\n"
		print Fore.WHITE + Style.BRIGHT + coffee

		#Create ssh sessions only to unqueried devices
		while True:
			if len(available_ips) == 0:
				break
			else:
				ip = available_ips[0]
				open_ssh_conn(ip, pass_list)
		
		print Fore.GREEN + Style.BRIGHT + "\n* Done!"
		
		#Create ssh threads
		create_ssh_threads(dev_manage_info)

		pid_set = set()
		sn_set = set()
		for host in dev_module_info.keys():
			for each_dict in dev_module_info[host][0]:
				pid_set.add(each_dict["pid"])
			for each_dict in dev_module_info[host][1]:
				sn_set.add(each_dict["serial_no"])

		pid_sn_dict = {"adapters": pid_set, "wics": sn_set}
		#pprint(pid_sn_dict)

		#soft_set = set()
		#for host in dev_ver_info:
			#soft_set.add((host["sys_type"], host["soft_ver"]))
		
		token_url = "https://cloudsso.cisco.com/as/token.oauth2"
		client_id = "wzxkkg83w8bgjp6kqg8p2eex"
		client_secret = "GCY7NPUTMSMFpgtQCecpAdFj"

		payload = {"grant_type":"client_credentials"}
		token = requests.post(token_url, data = payload, auth = (client_id, client_secret)).json()["access_token"]
		#print token

		eox_pid_url = "https://api.cisco.com/supporttools/eox/rest/5/EOXByProductID/1/"
		eox_sn_url = "https://api.cisco.com/supporttools/eox/rest/5/EOXBySerialNumber/1/"
		#soft_url = "https://api.cisco.com/supporttools/eox/rest/5/EOXBySWReleaseString/1/?"

		for item in pid_sn_dict["adapters"]:
			resp = requests.get(eox_pid_url + item + "?responseencoding=json", headers = {"Authorization": "Bearer %s" % token}).json()
			eox_info[item] = {"EndOfSaleDate": resp["EOXRecord"][0]["EndOfSaleDate"]["value"],
							"EndOfSWMaintenanceReleases": resp["EOXRecord"][0]["EndOfSWMaintenanceReleases"]["value"],
							"LastDateOfSupport": resp["EOXRecord"][0]["LastDateOfSupport"]["value"]}

		for item in pid_sn_dict["wics"]:
			resp = requests.get(eox_sn_url + item + "?responseencoding=json", headers = {"Authorization": "Bearer %s" % token}).json()
			eox_info[item] = {"EndOfSaleDate": resp["EOXRecord"][0]["EndOfSaleDate"]["value"],
							"EndOfSWMaintenanceReleases": resp["EOXRecord"][0]["EndOfSWMaintenanceReleases"]["value"],
							"LastDateOfSupport": resp["EOXRecord"][0]["LastDateOfSupport"]["value"]}

		"""for item in soft_set:
			resp = requests.get(soft_url + "input1=%s,%s" % (item[1], item[0]), headers = {"Authorization": "Bearer %s" % token}).json()
			eox_soft[item[1]] = {"EndOfSaleDate": resp["EOXRecord"][0]["EndOfSaleDate"]["value"],
							"EndOfSWMaintenanceReleases": resp["EOXRecord"][0]["EndOfSWMaintenanceReleases"]["value"],
							"LastDateOfSupport": resp["EOXRecord"][0]["LastDateOfSupport"]["value"]}"""

		#pprint(eox_soft)

		#Writing all the information to appropriate files
		write_cred_csv()
		write_module_info()
		write_iface_info()
		write_ver_info()

		#Draw network topology
		draw_topology()

		#Deinitialise colorama
		deinit()

	except KeyboardInterrupt:
		print Fore.RED + Style.BRIGHT + "\n* Program was stoped by the user"
		print "Bye"
		sys.exit()