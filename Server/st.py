#!/usr/bin/env python3.7

"""
Usage: st.py [--debug] [--resource-file <FILE>] [-h] [-v] 

Options:
    -h, --help                   Show this help message and exit
    -v, --version                Show version
    -r, --resource-file <FILE>   Read resource file
    -d, --debug                  Enable debug output
"""

import functools
import logging
import os
import traceback
import sys
from shlex import split

from docopt import docopt, DocoptExit
from prompt_toolkit import PromptSession
from prompt_toolkit.application import run_in_terminal
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.styles import Style
from termcolor import colored
from terminaltables import AsciiTable

import core.state as state
from core.listeners import Listeners
from core.modules import Modules
from core.sessions import Sessions
from core.stagers import Stagers
from core.servers import Servers
from core.utils import print_bad, print_banner

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
        self.prompt_session = PromptSession(
            'ST ≫ ',
            bottom_toolbar=bottom_toolbar,
            auto_suggest=AutoSuggestFromHistory(),
            enable_history_search=True,
            # rprompt=get_rprompt,
            # style=rprompt_style
        )

        self.contexts = [
            Listeners(self.prompt_session),
            Sessions(self.prompt_session),
            Modules(self.prompt_session),
            Stagers(self.prompt_session),
            Servers(self.prompt_session)
        ]

        self.prompt_session.completer = WordCompleter([ctx.name for ctx in self.contexts] + ['exit'], ignore_case=True)
        self.prompt_session.contexts = self.contexts

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
            elif result == 'help':
                table_data = [
                    ["Command", "Description"]
                ]

                try:
                    for cmd in self.current_context._cmd_registry:
                        table_data.append([cmd, getattr(self.current_context, cmd).__doc__.split('\n', 2)[1].strip()])

                    for menu in self.contexts:
                        if menu.name != self.current_context.name:
                            table_data.append([menu.name, menu.description])
                except AttributeError:
                    for menu in self.contexts:
                        table_data.append([menu.name, menu.description])

                table = AsciiTable(table_data)
                print(table.table)
                continue

            self.parse_result(result)


if __name__ == "__main__":
    codename = "尻目"
    version = "0.1.0dev"

    args = docopt(__doc__, version=f"{codename} - {version}")
    state.args = args

    logging.basicConfig(
        format="%(asctime)s %(process)d %(threadName)s - [%(levelname)s] %(filename)s: %(funcName)s - %(message)s",
        level=logging.DEBUG if args['--debug'] else logging.INFO,
        filename='./logs/ST.log',
        filemode='a'
    )

    logging.debug(args)

    os.system('cls' if os.name == 'nt' else 'clear')
    print_banner(codename, version)

    loop = CmdLoop()
    loop()
