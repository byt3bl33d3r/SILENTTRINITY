#!/usr/bin/env python3.7

"""
Usage: st.py [--debug] [--resource-file <FILE>] [-h] [-v] 

Options:
    -h, --help                   Show this help message and exit
    -v, --version                Show version
    -r, --resource-file <FILE>   Read resource file
    -d, --debug                  Enable debug output
"""

import logging
import functools
import os
import core.state as state
import traceback
from shlex import split
from docopt import docopt, DocoptExit
from core.listeners import Listeners
from core.sessions import Sessions
from core.modules import Modules
from core.stagers import Stagers
from core.utils import command, print_bad, print_good, print_info
from terminaltables import AsciiTable
from prompt_toolkit import PromptSession
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.application import run_in_terminal
from prompt_toolkit.styles import Style
from termcolor import colored

rprompt_style = Style.from_dict({
    'rprompt': 'bg:#ff0066 #ffffff',
})


def bottom_toolbar():
    return HTML(f"(Sessions: {state.SESSIONS} Listeners: {state.LISTENERS})")


def get_rprompt(error=False):
    return ' Error ' if error else ''


class UserExit(Exception):
    pass


class CmdLoop:

    def __init__(self):
        self.name = 'main'
        self.completer = WordCompleter(['listeners', 'sessions', 'modules', 'stagers', 'exit'], ignore_case=True)
        self.prompt_session = PromptSession(
            'ST ≫ ',
            bottom_toolbar=bottom_toolbar,
            completer=self.completer,
            auto_suggest=AutoSuggestFromHistory()
            #rprompt=get_rprompt,
            #style=rprompt_style
        )

        self.contexts = [
            Listeners(self.prompt_session),
            Sessions(self.prompt_session),
            Modules(self.prompt_session),
            Stagers(self.prompt_session)
        ]

        self.current_context = self

    def switched_context(self, result):
        for ctx in self.contexts:
            if result == ctx.name:
                self.prompt_session.message = ctx.prompt
                self.prompt_session.completer = ctx.completer
                self.current_context = ctx
                return True
        return False

    def parse_result(self, result):
        if len(result):
            if not self.switched_context(result):
                command = split(result)
                try:
                    logging.debug(f"command: {command[0]} args: {command[1:]} ctx: {self.current_context.name}")

                    bound_cmd_handler = functools.partial(getattr(self.current_context, command[0]), args=command[1:])
                    run_in_terminal(bound_cmd_handler)
                except AttributeError:
                    print_bad(f"Unknown command '{command[0]}'")
                    if args['--debug']:
                        traceback.print_exc()
                except DocoptExit as e:
                    print(str(e))
                except SystemExit:
                    pass

    def run_resource_file(self):
        with open(args['--resource-file']) as resource_file:
            for cmd in resource_file:
                result = self.prompt_session.prompt(accept_default=True, default=cmd.strip())
                self.parse_result(result)

    def __call__(self):
        if args['--resource-file']:
            self.run_resource_file()

        while True:
            result = self.prompt_session.prompt()
            if result == 'exit':
                break

            self.parse_result(result)


if __name__ == "__main__":

    codename = "Ánima"
    version = "0.0.1dev"

    banner = f"""
   _____ ______    _______   __________________  _____   ______________  __
  / ___//  _/ /   / ____/ | / /_  __/_  __/ __ \/  _/ | / /  _/_  __/\ \/ /
  \__ \ / // /   / __/ /  |/ / / /   / / / /_/ // //  |/ // /  / /    \  /
 ___/ // // /___/ /___/ /|  / / /   / / / _, _// // /|  // /  / /     / /
/____/___/_____/_____/_/ |_/ /_/   /_/ /_/ |_/___/_/ |_/___/ /_/     /_/

                         Codename: {colored(codename, "yellow")}
                         Version: {colored(version, "yellow")}
"""
    args = docopt(__doc__, version=f"{codename} - {version}")

    state.args = args

    os.system('cls' if os.name == 'nt' else 'clear')

    logging.basicConfig(
        format="%(asctime)s %(process)d %(threadName)s - [%(levelname)s] %(filename)s: %(funcName)s - %(message)s",
        level=logging.DEBUG if args['--debug'] else logging.INFO
    )

    logging.info(args)

    print(banner)
    loop = CmdLoop()
    loop()
