#!/usr/bin/env python3

import socket
import sys
import shodan
import nmap
import argparse
import colorama
import time

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8", 80))
ipaddress = s.getsockname()[0]
s.close()
nma = nmap.PortScannerAsync()

SHODAN_API_KEY = "YOUR_SHODAN_API_KEY"
target = ''
subnet = False
full = False
vuln = False
external = ''

# This is where we will send our data to the shodan api in order to see if there are any potential vulnerabilities.
def checkVulns(host, scandata):
    global SHODAN_API_KEY
    for k, item in scandata.items():
        # print(item)
        if str(item['product']) != '' and str(item['version']) != '':
            strSearch = item['product'] + ' ' + item['version']

            # The idea here is to parse through the scandata and construct strings to pass to the exploit api.
            try:
                # Search Shodan
                api = shodan.Shodan(SHODAN_API_KEY)
                results = api.exploits.search(strSearch)

                # Show the results
                if results['total'] >= 1:
                    print(host + ' ' + str(k), colorama.Fore.RED + strSearch + colorama.Fore.RESET)
                else:
                    print(host + ' ' + str(k), colorama.Fore.GREEN + strSearch + colorama.Fore.RESET)
            except shodan.APIError as e:
                print(host + 'Search Term: ' + strSearch + ' Error: %s' % e)
        time.sleep(2)


def callback_result(host, scan_result):
    global vuln
    if int(scan_result['nmap']['scanstats']['uphosts']) >= 1:
        if vuln:
            if 'tcp' in scan_result['scan'][host]:
                checkVulns(host, scan_result['scan'][host]['tcp'])

                # print(host, scan_result['scan'])
                # grab_banner(host, scan_result["scan"][host]["tcp"])
                # print("------")

def doscan(host):
    nma.scan(hosts=host, callback=callback_result)
    while nma.still_scanning():
        nma.wait(2)

def main():
    global target
    global vuln
    global full
    global external
    global SHODAN_API_KEY
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

    if args.f:
        full = True
        api = shodan.Shodan(SHODAN_API_KEY)
        external = api.tools.myip()
    if args.v:
        vuln = True

    doscan(target)

    if full:
        doscan(external)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
