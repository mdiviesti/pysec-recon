#!/usr/bin/env python3

import os
import socket
import sys
import nmap
import colorama

# Python3 input behaves like previous raw_input.
# solving for that in the event that we are using Python2
try:
    input = raw_input
except NameError:
    pass

if os.getenv("SUDO_USER") == None:
    print(colorama.Fore.RED + 'WARNING: Pulling Mac addresses and some other useful information requires \'sudo\'. ' + colorama.Fore.RESET)
    respSudo = input("Would you like to continue without sudo [Y]es [N]o: ")
    if respSudo in ['N', 'n']:
        exit(0)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8", 80))
ipvarsplit = s.getsockname()[0].split(".")
s.close()
ipaddreplace = ipvarsplit[:-1] + ["0/24"]
ipvar = '.'.join(ipaddreplace)
print(ipvar)
nma = nmap.PortScannerAsync()


def printr(d):
    for k, v in d.items():
        print(k, v)


# grab the banner
def grab_banner(ip_address, scanres):
    for k, v in scanres.items():
        try:
            s = socket.socket()
            s.connect((ip_address, k))
            banner = s.recv(1024)
            s.close()
            print(ip_address, k, banner)
        except Exception as e:
            print(e)
            continue


def checkVulns(host, port, scandata):
    if len(sys.argv) >= 2:
        filename = sys.argv[1]
        for line in filename.readlines():
            line = line.strip('\n')
            if banner in line:
                print("%s is vulnerable" % banner)
            else:
                print("%s is not vulnerable" % banner)


def callback_result(host, scan_result):
    if int(scan_result['nmap']['scanstats']['uphosts']) >= 1:
        print("------")
        print(host, scan_result)
        # grab_banner(host, scan_result["scan"][host]["tcp"])
        # print("------")


def main():
    nma.scan(hosts=ipvar, callback=callback_result)
    while nma.still_scanning():
        nma.wait(2)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
