# SIEMS FRAMEWORK

MultiSIEM Modular Python3 Attack Framework 
By ElevenPaths https://www.elevenpaths.com/                                                                                   
Usage: python3 ./siemsframework.py   

## INTRODUCTION

SIEMs are defensive tools increasingly used in the field of cybersecurity, especially by major companies and companies intended to monitor highly critical systems and networks. However, from the point of view of an attacker, those permissions granted to SIEMs on systems and accounts from corporate networks are high. Moreover, administrative access to SIEMs may be used to obtain code execution on the server where such SIEM is installed, and sometimes also on client machines, considering that a SIEM collects events such as Active Directory servers, AWS servers, Data Bases and network devices (for example, Firewalls and Routers).

During our investigation, we detected a great amount of attack vectors that might be used on the various SIEMs to compromise them, for instance:
•	Obtain user accounts and passwords stored in the SIEM from critical systems (LDAP/AD servers, databases, network devices, AWS servers).
•	Develop and install malicious applications such as Windows/Linux reverse shells, Windows/Linux bind shells or malicious scripts with the aim of compromising the server where the SIEM is installed.
•	Develop and install malicious applications such as Windows/Linux reverse shells, Windows/Linux bind shells or malicious scripts with the aim of compromising the machines from which the SIEM collects events.
•	Create and apply malicious actions or notifications that allow to execute commands when a given event occurs, for example with the purpose of obtaining a reverse shell on the server where the SIEM is installed.
•	Take advantage of default passwords and SIEM weaknesses in the OVA images configuration to obtain admin credentials of the server, database or even the SIEM web interface itself.
•	Perform dictionary attacks or brute-force attacks against the web or admin interface, or against the SIEM client software, to obtain admin credentials.
•	Read arbitrary files from the server where the SIEM is installed.
•	Obtain SIEM configuration information and other relevant parameters to perform further attacks.
On the basis of the investigation results, the tool Open Source SIEMs Framework was developed. It is a modular tool developed in Python3 by the Innovation and Laboratory team of ElevenPaths. It allows to automatize potential attacks to various SIEMs existing in the market (both commercial and open source).

SIEMs Framework supports multiple attack payloads that may be selected according the SIEM to be attacked and its operating system. There are payloads available in PowerShell, Python, Bash, Exe, and more formats. Once the selected attack is executed, the tool shows the results on the screen and it is possible to return and execute any other attack on the same SIEM or select other SIEM to compromise. It has a simple, easy-to-use and intuitive interface. Currently it can be used with the following SIEMs: Splunk, Graylog and OSSIM.

## DOWNLOADING, REQUIREMENTS AND INSTALLATION

SIEMs Framework can be downloaded from our Github by downloading the .zip file or cloning the repository, and presents the following requirements that can be installed through pip3 install -r requirements.txt:

•	splunk-sdk
•	requests
•	python-nmap
•	colorama
•	pandas
•	paramiko
•	pymongo

Once the requirements installed, the tool can be used as follows: python3 ./siemsframework.py

## TOOL USAGE

When the tool is executed, the main menu is displayed, and there you must select if you wish to scan a specific IP where there would be a SIEM or a network to detect those SIEMs within it. For scanning and detecting the SIEM within a specific IP address you must use option 1, and for scanning the network option 2.
### Scanning a specific IP
By selecting option 1 “Scan and Detect SIEM”, the tool requests the IP address to be able to scan the specific ports of the SIEMs supported and connect to either web or management interface in order to verify that it is really a SIEM.
 
Once the SIEM has been detected by following the above methods, the tool shows the SIEM detected in red and gives you the option to launch the attack module of that SIEM.
### Network Scanning
By selecting option 2 “Find SIEMs on the network” the tool requests the network to be scanned in CIDR notation, for instance: 192.168.137.0/24. Once the information is entered, SIEMs Framework performs firstly a discovery to detect the active systems; then, default ports of the SIEMs supported are scanned, and finally it connects to either web or management interface of each of those systems in order to verify that it is really a SIEM.
 
Once the SIEMs have been detected by following the above methods, the tool shows the SIEMs detected in red and requests the IP address of the SIEM to be attacked.

### Splunk Attack Modules
#### 1st Attack: Dictionary Attack on Splunk Admin Interface 
This attack module contains a specific dictionary for Splunk named dict.txt, which is made up of the 100 most used password over 2018 and various permutations of the SIEM trade name and its admin user, in uppercase and lowercase letters, and replacing vowels with numbers. In case you wish to use any other list different from the one mentioned above, /splunk/dict.txt can be replaced with any other word list, provided that the file name is kept. Splunk password policy does not apply to users with admin role, so restrictions concerning password or account blocking due to unsuccessful access attempts do not apply.
Prior to starting the dictionary attack, the tool verifies if the Splunk to be analyzed has the Free version that does not use any type of authentication, or if it still keeps the default password “changeme” of the oldest versions of this software:
 
#### 2nd Attack: Obtain Server and Session Information via Web Interface
In case the Splunk server to be analyzed has the web interface active, this module allows to obtain server and session information from the web interface itself without needing to authenticate. 8000 is the default port of Splunk web interface; to use this module it is necessary to know and enter the port where the web interface is published.
 
#### 3rd Attack: Obtain System Information via Management Port
This module can be used on Splunk Server or Universal Forwarder. To use it, Splunk Admin credentials are needed, and they can be obtained for instance through a dictionary attack (1st attack). The result of the module is the information of the current Splunk installation: version, operating system, Splunk configurations and more.
 
#### 4th Attack: Obtain Splunk Stored Passwords
This module is only used on Splunk servers. To use it, Splunk admin credentials are needed, and they can be obtained for instance through a dictionary attack (1st attack). The result of the module are all the credentials stored by those apps used on Splunk to connect to those devices from which events are obtained.

#### 5th Attack: Read /etc/shadow file from Splunk server (Linux only)
This module can be used on Linux Splunk Server. To use it, Splunk admin credentials are needed, and they can be obtained for instance through a dictionary attack (1st attack). The module uses an index to load the file concerned, and its result is the content of the file /etc/shadow from the server where Splunk is installed.
 
#### 6th Attack: Deployment of Malicious Applications to UF
This module will be available in the next version of SIEMs Framework. In order to compromise Universal Forwarders, attack 1 to obtain credentials and then attack 7 to install malicious applications depending on the platform may be performed so far.
#### 7th Attack: Install Malicious Application to Compromise Splunk/UF Server
This attack module allows to develop and install on Splunk a malicious application designed to compromise the system concerned. Firstly, the type of payload to be used according to the operating system and the type of Splunk to attack must be selected (Splunk Server or Universal Forwarder). You can use Linux Python Reverse or Bind Shell for Splunk Server or UF; Windows Python Reverse or Bind Shell for Splunk Server (where Python is installed by default); and Executable Bind Shell or a script to add an admin user on Windows Universal Forwarders (where Python is not installed by default). Then, username, Splunk admin password and the attacker’s IP address must be entered.


### Graylog Attack Modules

By entering “y” and selecting the launch of Graylog attack modules, the tool shows all the possible attacks to be performed against this SIEM. For the first three attacks no credentials are required, but for the fourth one Graylog admin privileges are needed.
 
#### 1st Attack: Dictionary Attack on Graylog Web Interface
This attack module contains a specific dictionary for Graylog named dict.txt, which is made up of the 100 most used password over 2018 and various permutations of the SIEM trade name and its admin user, in uppercase and lowercase letters, and replacing vowels with numbers. In case you wish to use any other list different from the one mentioned above, /graylog/dict.txt can be replaced with any other word list, provided that the file name is kept.
 
#### 2nd Attack: Test for Graylog AMI/OVA Default Credentials
This attack module verifies if the Graylog to be analyzed has default credentials on Graylog web interface (admin/admin), as well as if it has default credentials to connect to the system by console or SSH (ubuntu/ubuntu). These couple of credentials are configured by default on Graylog virtual machine appliances, both on OVA and AMI.
 
#### 3rd Attack: Test connection to MongoDB and Obtain Credentials for LDAP and AWS
This attack module verifies if the Graylog to be analyzed has Mongo DB database configured with no authentication. In such a case, it connects to MongoDB and obtains configuration information, LDAP credentials (depending on the current Graylog version they may be in plain text or encrypted) and access and secret keys configured in the AWS plugin. In case it is encrypted, LDAP user key is encrypted with AES CBC. They key is the first 16 bits of the field password_secret, located in the configuration file server.conf, or graylog.conf in case of standard installations; or the field secret_token located in the file graylog-secrets.json in case of OVA installations, the IV is the salt showed on the screen.
 
#### 4th Attack: Obtain Credentials for LDAP and AWS from REST API
This attack module obtains information on configuration and credentials for LDAP and AWS in plain text from Graylog REST API. To use this module Graylog admin credentials are needed.


### Ossim Attack Modules
By entering “y” and selecting the launch of OSSIM attack modules, the tool shows all the possible attacks to be performed against this SIEM. For the first attack no credentials are required, but for the subsequent ones OSSIM admin credentials are needed.
 
#### 1st Attack: Dictionary Attack on OSSIM Web Interface
This attack module contains a specific dictionary for OSSIM named dict.txt, which is made up of the 100 most used password over 2018 and various permutations of the SIEM trade name and its admin user, in uppercase and lowercase letters, and replacing vowels with numbers. In case you wish to use any other list different from the one mentioned above, /ossim/dict.txt can be replaced with any other word list, provided that the file name is kept.
 
#### 2nd Attack: Obtain OSSIM Configuration Information
This attack module allows to obtain configuration information from OSSIM server. To use it, OSSIM admin credentials are needed, and they can be obtained for instance through a dictionary attack (1st attack). The result of the module is the relevant configuration information of the current installation: defined users, login parameters including LDAP configurations and password policies.
 
####  3rd Attack: Configure Malicious Policy and Action to Obtain Reserve Shell on OSSIM
This attack module allows to obtain a reverse shell from OSSIM server to the attacker’s system. To use it, OSSIM admin credentials are needed, and they can be obtained for instance through a dictionary attack (1st attack). The module develops a malicious action that will be connected via netcat to the attacker’s system. Then, it triggers a new policy that uses such action to warn in case any security event occurs, and this event is triggered through an unsuccessful SSH login attempt to OSSIM server. Consequently, a reverse shell is obtained from the OSSIM server to the attacker’s system in port 12345 with root privileges.

## CONTRIBUTING AND SUPPORT

Please report any error by opening an issue in GitHub. Your collaboration is very appreciated!