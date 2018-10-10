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
from core.utils import print_good, print_info, print_bad, get_ipaddress


def validate_stager(stager):
    stagers = Loader()
    stagers.type = "stager"
    stagers.paths = ["stagers/"]
    stagers.name = 'stagers'

    stagers.selected = None

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
    listeners.name = 'listeners'

    listeners.get_loadables()

    for l in listeners.loaded:
        if l.name == listener.name:
            l['BindIP'] = listener['BindIP']
            l['Port'] = listener['Port']
            return l

    return None


def generate_stager(stager, listener):
    stager.generate(listener)


def generate_resource_file(stager, listener):
    filename = "{}.res".format(stager)

    resource_file = open(filename, 'w')
    resource_file.write("listeners\n")
    resource_file.write("use {}\n".format(listener.name))
    resource_file.write("set BindIP {}\n".format(listener['BindIP']))
    resource_file.write("set Port {}\n".format(listener['Port']))
    resource_file.write("start")
    resource_file.close()

    print_good(f"Generated resource file: {filename}")
    print_info(f"Launch with 'python3.7 st.py -r {filename}'")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("stager", help="Stager method", type=str)
    parser.add_argument("listener", help="Listener protocol", type=str)
    parser.add_argument("port", help="Bind Port", type=int)
    parser.add_argument("--ip", dest='ip', help="Bind IP address", type=str, required=False)
    parser.add_argument("--file", dest='file', help="Filename", type=str, required=False)

    args = parser.parse_args()

    stager = validate_stager(args.stager)

    if stager is None:
        print_bad("ERROR: Invalid stager.")
        sys.exit(1)

    listener = generate_listener(args.ip, args.port)
    listener = validate_listener(listener)

    if listener is None:
        print_bad("ERROR: Invalid listener.")
        sys.exit(1)

    generate_stager(stager, listener)

    filename = stager.name
    if args.file is not None:
        filename = args.file

    generate_resource_file(filename, listener)

    sys.exit(0)
