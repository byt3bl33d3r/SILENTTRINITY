import netifaces
import random
import string
from typing import get_type_hints, List, Dict
from functools import wraps
from docopt import docopt
from termcolor import colored
from quart import jsonify
from uuid import UUID


class CmdError(Exception):
    pass


def command(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        cmd_args = docopt(func.__doc__.strip(), argv=kwargs["args"])
        validated_args = {}
        for name, hint in get_type_hints(func).items():
            try:
                value = cmd_args[f'<{name}>']
            except KeyError:
                try:
                    value = cmd_args[f'--{name}']
                except KeyError:
                    raise CmdError(f"Unable to find '{name}' argument in command definition")

            try:
                validated_args[name] = hint(value)
            except TypeError:
                # I'm still not sure if there's a way to dynamically cast Lists and Dicts using type hints
                if hint == List[int]:
                    validated_args[name] = [int(x) for x in value]
                elif hint == List[str]:
                    validated_args[name] = [str(x) for x in value]
                else:
                    raise NotImplemented(f"Casting for type '{hint}' has not been implemented")

        return func(args[0], **validated_args)
    return wrapper


def check_valid_guid(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            UUID(kwargs["GUID"])
        except Exception:
            return jsonify({}), 400
        return func(*args, **kwargs)
    return wrapper


def gen_random_string(length=8):
    return ''.join(random.sample(string.ascii_letters, int(length)))


def get_interfaces():
    return netifaces.interfaces()


def get_ipaddress(interface=None):
    if interface and (interface in get_interfaces()):
        return netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']
    else:
        for iface in ['eth0', 'en0']:
            try:
                return netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr']
            except (ValueError, KeyError):
                continue

            return ""


# https://github.com/zerosum0x0/koadic/blob/master/core/plugin.py
def convert_shellcode(shellcode):
    decis = []
    count = 0
    for i in range(0, len(shellcode), 2):
        count += 1
        hexa = shellcode[i:i + 2]
        deci = int(hexa, 16)

        if count % 25 == 0:
            decis.append(" _\\n" + str(deci))
        else:
            decis.append(str(deci))

    return ",".join(decis)


def print_good(msg):
    print(f"{colored('[+]', 'green')} {msg}")


def print_bad(msg):
    print(f"{colored('[-]', 'red')} {msg}")


def print_info(msg):
    print(f"{colored('[*]', 'blue')} {msg}")
