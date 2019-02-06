import functools
from core.loader import Loader
from typing import List
from core.utils import command, register_cli_commands, print_bad, print_info, print_bad
from core.completers import STCompleter
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.application import run_in_terminal
from terminaltables import AsciiTable


@register_cli_commands
class Stagers(Loader):

    def __init__(self, prompt_session):
        Loader.__init__(self)
        self.type = "stager"
        self.paths = ["stagers/"]

        self.name = 'stagers'
        self.prompt = HTML('ST (<ansired>stagers</ansired>) ≫ ')

        self.completer = STCompleter(self)
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
            for l in self.prompt_session.contexts[0].listeners:
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
                self.prompt_session.message = self.prompt = HTML(f"ST (<ansired>stagers</ansired>)(<ansired>{s.name}</ansired>) ≫ ")

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
