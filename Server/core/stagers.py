import functools
from core.loader import Loader
from typing import List
from core.events import GET_LISTENERS
from core.utils import command
from core.ipcserver import ipc_server
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.application import run_in_terminal
from terminaltables import AsciiTable
from core.utils import print_bad, print_info, print_bad


class Stagers(Loader):

    def __init__(self, prompt_session):
        Loader.__init__(self)
        self.type = "stager"
        self.paths = ["stagers/"]

        self.name = 'stagers'
        self.prompt = HTML('ST (<ansired>stagers</ansired>) ≫ ')

        self.completer = WordCompleter(['use', 'set', 'options', 'sessions', 'list', 'modules', 'listeners', 'generate', 'exit'], ignore_case=True)
        self.prompt_session = prompt_session

        self.selected = None
        self.get_loadables()

    @command
    def list(self):
        """
        Get available stagers

        Usage: list [-h]
        """
        table_data = [
            ["Name", "Description"]
        ]
        for l in self.loaded:
            table_data.append([l.name, l.description])

        table = AsciiTable(table_data, title="Available")
        table.inner_row_border = True
        print(table.table)

    @command
    def generate(self, listener_name: str):
        """
        Generate the selected stager

        Usage: generate <listener_name> [-h]

        Arguments:
            listener_name   listener name
        """

        if self.selected:
            listeners = ipc_server.publish(GET_LISTENERS, '')

            for l in listeners:
                if l['Name'] == listener_name.lower():
                    self.selected.generate(l)
        else:
            print_bad("No stager selected")

    @command
    def use(self, name: str):
        """
        Select the specified stager

        Usage: use <name> [-h]

        Arguments:
            name  name of stager
        """

        for s in self.loaded:
            if s.name == name.lower():
                self.selected = s

                new_prompt = HTML(f"ST (<ansired>stagers</ansired>)(<ansired>{s.name}</ansired>) ≫ ")
                self.prompt_session.message = new_prompt
                self.prompt = new_prompt

    @command
    def set(self, name: str, value: str):
        """
        Set options on the selected stager

        Usage: set <name> <value> [-h]

        Arguments:
            name   option name
            value  option value
        """

        if self.selected:
            try:
                self.selected[name] = value
            except KeyError:
                print_bad(f"Unknown option '{name}'")

    @command
    def options(self):
        """
        Show selected stager options

        Usage: options [-h]
        """

        if self.selected:
            table_data = [
                ["Option Name", "Required", "Value", "Description"]
            ]

            for k, v in self.selected.options.items():
                table_data.append([k, v["Required"], v["Value"], v["Description"]])

            table = AsciiTable(table_data)
            table.inner_row_border = True
            print(table.table)
        else:
            print_bad("No stager selected")
