#! /usr/bin/env python3

"""
Usage: st [-h] [-v] (client|teamserver) [<args>...]

options:
    -h, --help                   Show this help message and exit
    -v, --version                Show version
"""

from docopt import docopt
from silenttrinity import VERSION


def run():
    args = docopt(__doc__, version=VERSION, options_first=True)
    if args['client']:
        import silenttrinity.core.client.__main__ as client
        client.start(docopt(client.__doc__, argv=args["<args>"]))
    elif args['teamserver']:
        import silenttrinity.core.teamserver.__main__ as teamserver
        teamserver.start(docopt(teamserver.__doc__, argv=args["<args>"]))
