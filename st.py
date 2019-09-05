#!/usr/bin/env python3

"""
Usage: silenttrinity.py [-h] [-v] [-d] [--resource-file <FILE>] [<URL>...]

arguments:
    URL   teamserver url(s)

options:
    -h, --help                   Show this help message and exit
    -v, --version                Show version
    -r, --resource-file <FILE>   Read resource file
    -d, --debug                  Enable debug output
"""

import asyncio
import logging
from docopt import docopt
from core.utils import print_banner
from core.client.cmdloop import STShell

VERSION = "0.4.0dev"
CODENAME = "Zuiikin' English"

async def main(args):
    s = STShell(args)
    print_banner(CODENAME, VERSION)
    await s.cmdloop()

if __name__ == '__main__':
    args = docopt(__doc__, version=VERSION)
    log_level = logging.DEBUG if args['--debug'] else logging.INFO
    logging.basicConfig(format="%(asctime)s [%(levelname)s] - %(filename)s: %(funcName)s - %(message)s", level=log_level)
    logging.getLogger('websockets').setLevel(log_level)

    asyncio.run(main(args))
