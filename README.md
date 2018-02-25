# An automated solution to document the environment

The solution uses TextFSM module for parsing semi-formatted text. templates folder contains TextFSM templates which is used during the execution of the script. IMPORTANT: do not delete these files and do not change the number of values in them. In order to adjust the solution to different devices just modify the searching lines(after "Start" word). The script was tested on Cisco 2691 routers with 12.4(25d) software version.

To run the script use:
./topology.py range.txt password.txt or python topology.py range.txt password.txt

The script takes two arguments:

range.txt - file contains ip address ranges of your network(not a specific ip addresses) in the following format: 172.16.0.0/30,172.16.0.4/30,............

password.txt - file contains passwords for your network devices(script automatically will find appropriate passwords for each device).Each line in the file should be a specific password.

Note: adjust these files to your network topology! In order to execute script successfully all devices in the network should have SSH server configured(create RSA keys for each device)!

As a result script creates the following files:

./results/dev_credentials.csv - contains management information for all devices in the network; 

./results/dev_general.txt - contains hardware version and OS version information for each device("show version" command);

./results/dev_interfaces.txt - contains interface description and interface status and more for each interface on each device;

./results/dev_modules.txt - contains information about modules which are installed on the device - and status of each module.

The solution also draws network topology and creates .png file which you can save where you want.
