#!/usr/bin/env python3.7

"""
Generate a stager for SILENTTRINITY

usage: stvenom.py [-h] [--ip IP] [--file FILE] stager listener port

positional arguments:
  stager       Stager method
  listener     Listener protocol
  port         Bind Port

optional arguments:
  -h, --help   show this help message and exit
  --ip IP      Bind IP address
  --file FILE  Filename
"""

import argparse
import sys

from core.listener import Listener
from core.loader import Loader
from core.utils import print_good, print_bad, get_ipaddress


def validate_stager(stager):
    stagers = Loader()
    stagers.type = "stager"
    stagers.paths = ["stagers/"]

    stagers.get_loadables()

    for s in stagers.loaded:
        if s.name == stager.lower():
            return s

    return None


def generate_listener(ip, port):
    listener = Listener()
    listener.name = args.listener

    if ip is None:
        ip = get_ipaddress()

    listener.options = {
        'BindIP': {'Description': 'The IPv4/IPv6 address to bind to.', 'Required': True, 'Value': ip},
        'Port': {'Description': 'Port for the listener.', 'Required': True, 'Value': port}}
    return listener


def validate_listener(listener):
    listeners = Loader()
    listeners.type = "listener"
    listeners.paths = ["listeners/"]

    listeners.get_loadables()

    for l in listeners.loaded:
        if l.name == listener.name:
            l['BindIP'] = listener['BindIP']
            l['Port'] = listener['Port']
            return l

    return None


def generate_resource_file(stager, listener):
    filename = f"{stager}.res"
    with open(filename, 'w') as resource_file:
        resource_file.write("listeners\n")
        resource_file.write(f"use {listener.name}\n")
        resource_file.write(f"set BindIP {listener['BindIP']}\n")
        resource_file.write(f"set Port {listener['Port']}\n")
        resource_file.write("start\n")
        resource_file.write("modules")

    print_good(f"Generated resource file: {filename}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("stager", help="Stager method", type=str)
    parser.add_argument("listener", help="Listener protocol", type=str)
    parser.add_argument("port", help="Bind Port", type=int)
    parser.add_argument("--ip", dest='ip', help="Bind IP address", type=str, required=False)
    parser.add_argument("--file", dest='file', help="Filename", type=str, required=False)

    args = parser.parse_args()

    stager = validate_stager(args.stager)

    stager_file = None
    resource_file = stager.name
    if args.file is not None:
        resource_file = args.file
        stager_file = args.file

    if stager is None:
        print_bad("ERROR: Invalid stager.")
        sys.exit(1)

    listener = generate_listener(args.ip, args.port)
    listener = validate_listener(listener)

    if listener is None:
        print_bad("ERROR: Invalid listener.")
        sys.exit(1)

    stager.generate(listener, stager_file)

    generate_resource_file(resource_file, listener)

    sys.exit(0)
