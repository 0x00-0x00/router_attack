#!/usr/bin/env python
import argparse
import requests
import base64
import httplib

def patch_send():
    old_send = httplib.HTTPConnection.send
    def new_send(self, data):
        print data
        return old_send(self, data)
    httplib.HTTPConnection.send = new_send
patch_send() # Debug patch

def login(ip, user, password):
    cookies = {"Authorization": "Basic " + base64.b64encode("{0}:{1}".format(user, password))}
    headers = {"Referer":"http://{0}/info.html".format(ip)}
    req = requests.get("http://{0}/info.html".format(ip), cookies=cookies)
    return req.status_code, req.text


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--ip", type=str, default="192.168.1.1",
            required=True, help="Router IP")
    args = parser.parse_args()
    error_code, data = login(args.ip, "admin", "erlon227")
    print(error_code)
    print(data)
    return 0


if __name__ == "__main__":
    main()
