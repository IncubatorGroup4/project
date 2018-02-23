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


#Create all the necessary variables

#List of available ips
available_ips = []

#List (of dictionaries) of management information for each device
dev_manage_info = []


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
		except paramiko.ssh_exception.NoValidConnectionsError:
			ssh_check = False
			print Fore.RED + Style.BRIGHT + "\n Too many vty connections to device --> " + ip
			print Fore.WHITE + Style.BRIGHT + "\n"
			break
		except socket.error as err:
			ssh_check = False
			print Fore.RED + Style.BRIGHT + "*\n Error: " + str(err)
			print Fore.WHITE + Style.BRIGHT + "\n"
			break

	#Evaluate ssh_check flag
	if ssh_check == True:
		#Create a shell to execute commands
		conn =  ssh_client.invoke_shell()

		conn.send("terminal length 0\n")

		conn.send("show ip interface brief\n")
		time.sleep(1)

		conn.send("show running-config | include hostname\n")
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

def gather_info(ssh_client, conn):
	"""Gather all the neccessary information for a device. Accepts paramiko.SSHClient() object"""

	conn.send("show running-config | include hostname\n")
	time.sleep(1)

	############################

	#Add your commands here

	############################

	output = conn.recv(1000)

	#Find device hostname
	dev_hostname = re.search(r"hostname (\S+)\s*", output)
	if dev_hostname != None:
		hostname = dev_hostname.group(1)
		#Add to a dictionary hostname
		for dev in dev_manage_info:
			if dev["ssh_client"] == ssh_client:
				dev["hostname"] = hostname

	#Close SSH session
	ssh_client.close()

def create_ssh_threads(ssh_list):
	"""Creates threads for each ssh_client in ssh_list."""

	threads = []
	for dev in ssh_list:
		th = threading.Thread(target = gather_info, args = (dev["ssh_client"], dev["shell"]))
		th.start()
		threads.append(th)
		time.sleep(1)

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
		pprint(dev_manage_info)
		print "\n"

		create_ssh_threads(dev_manage_info)
		pprint(dev_manage_info)


		#print "\n Device  credentials: "
		#pprint(dev_manage_info)

		#write_cred_csv()

		#Deinitialise colorama
		deinit()

	except KeyboardInterrupt:
		print Fore.RED + Style.BRIGHT + "\n* Program was stoped by the user"
		print "Bye"
		sys.exit()