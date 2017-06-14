#!/usr/bin/env python
import requests
import argparse
import subprocess

def get_gw(ip):
    data = subprocess.check_output("arp -a | grep {0}".format(ip))
    return data


DEFAULT_PAGE = "http://{0}/padrao"

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--ip", type=str, required=True, help="OpenRG router IP address")
    args = parser.parse_args()
    LOGIN_PAGE = DEFAULT_PAGE.format(args.ip)

    print("[+] Trying to connect to default page: {0}".format(LOGIN_PAGE))
    req = requests.get(LOGIN_PAGE)

    return 0

if __name__ == "__main__":
    main()
