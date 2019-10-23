#!/usr/bin/env python3

"""
Usage: client [-h] [-d] [--resource-file <FILE>] [<URL>...]

arguments:
    URL   teamserver url(s)

options:
    -h, --help                   Show this help message and exit
    -r, --resource-file <FILE>   Read resource file
    -d, --debug                  Enable debug output
"""

import logging
import asyncio
from silenttrinity import VERSION, CODENAME
from silenttrinity.core.utils import print_banner
from silenttrinity.core.client.cmdloop import STShell

async def main(args):
    s = STShell(args)
    print_banner(CODENAME, VERSION)
    await s.cmdloop()

def start(args):
    log_level = logging.DEBUG if args['--debug'] else logging.INFO
    logging.basicConfig(format="%(asctime)s [%(levelname)s] - %(filename)s: %(funcName)s - %(message)s", level=log_level)
    logging.getLogger('websockets').setLevel(log_level)
    asyncio.run(main(args))
