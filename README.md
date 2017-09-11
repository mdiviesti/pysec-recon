# pysec-recon
pysec-recon is a basic automation script which leverages existing 
libraries in order to automate the recon process when attempting to 
assess your network's security posture. 

# Requirements
* Python 2 or 3
* Mac or Linux (untested in windows)
* python-nmap (recommend: installed with pip)
* colorama (recommend: installed with pip)

# Getting Started
Make sure that Python 2 or greater is installed.
Install python-nmap and colorama. 

```
git clone https://github.com/mdiviesti/pysec-recon.git
cd pysec-recon
chmod a+x pysec-recon.py
sudo ./pysec-recon.py
```
Note: While you can, technically, run pysec-recon without sudo, 
the nmap library (which we are tapping into) will not be able to 
pull Mac addresses and it may not be able to determine all open 
ports, port protocols, or protocol versions, firmware versions, 
and other useful data.

# Usage: 
```
usage: pysec-recon.py [-h] [-t T] [-s] [-f] [-v]

pysec-recon automates the recon process of security posture assessment.
Requires python-nmap, shodan, and argparse. You can combine multiple options
-sfv for instance

optional arguments:
  -h, --help  show this help message and exit
  -t T        Target IP Address. If you do not specify one, your current IP
              address will be detected and used
  -s          Subnet Scan: Scans all ip addresses in the subnet of the
              provided address
  -f          Full scan: Scans internal and external ip
  -v          Vulnerability Scan: check for vulnerabilities in all found ips
              and ports
Author: Michael Diviesti @michael_atx on twitter
```
# Features
* Determines your internal ip address
* Scans ip addresses on your subnet
* Scans for ports on those IP addresses

# Current State
At the moment, the script just automates the above three items and spits out a JSON string with all of information assessed from an nmap scan.
This is very beginning stages. 

# Future Features
The direction I'm taking this project is, now that the script has grabbed information about open ports, we can use that information to automatically search Shodan for known vulnerabilities that exist on your system.
The goal here is not to automate the process of gaining entry into the system, rather, it is to automate the process of finding **POTENTIAL** holes in your system. 
