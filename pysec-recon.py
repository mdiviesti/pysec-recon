#!/usr/bin/env python3

import socket
import sys
import shodan
import nmap
import argparse

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8", 80))
ipaddress = s.getsockname()[0]
s.close()
nma = nmap.PortScannerAsync()

# This is where we will send our data to the shodan api in order to see if there are any potential vulnerabilities.
def checkVulns(host, port, scandata):
    print('Vulnerability Scanner is a work in progress at the moment. ')
    SHODAN_API_KEY = "Your API Key"

    api = shodan.Shodan(SHODAN_API_KEY)
    #The idea here is to parse through the scandata and construct strings to pass to the exploit api.
    try:
        # Search Shodan
        results = api.exploits.search('PHP 5.6')

        # Show the results
        print('Results found: %s' % results['total'])
        for result in results['matches']:
            print('IP: %s' % result)
            #print(result['data'])
            print('')
    except shodan.APIError as e:
        print('Error: %s' % e)

def callback_result(host, scan_result):
    if int(scan_result['nmap']['scanstats']['uphosts']) >= 1:
        print("------")
        print(host, scan_result['scan'])
        # grab_banner(host, scan_result["scan"][host]["tcp"])
        # print("------")

def main():
    parser = argparse.ArgumentParser(
        description='''pysec-recon automates the recon process of security posture assessment. Requires python-nmap, shodan, and argparse. You can combine multiple options -sfv for instance''',
        epilog="""Author: Michael Diviesti @michael_atx on twitter""")
    parser.add_argument('-t', type=str, default=ipaddress,
                        help='Target IP Address. If you do not specify one, your current IP address [' + ipaddress + '] will be used')
    parser.add_argument('-s', action='store_true',
                        help='Subnet Scan: Scans all ip addresses in the subnet of the provided address')
    parser.add_argument('-f', action='store_true', help='Full scan: Scans internal and external ip')
    parser.add_argument('-v', action='store_true',
                        help='Vulnerability Scan: check for vulnerabilities in all found ips and ports')
    args = parser.parse_args()

    if args.s:
        targetlist = args.t.split(".")
        target = '.'.join(targetlist[:-1] + ["0/24"])
    else:
        target = args.t
    print('scanning ' + target)
    # if args.f:
    #     print(args.f)
    # if args.v:
    #     print(args.v)

    nma.scan(hosts=target, callback=callback_result)
    while nma.still_scanning():
        nma.wait(2)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
