from core.loader import Loader
from typing import List
from core.job import Job
from core.utils import command, register_cli_commands
from core.events import NEW_JOB
from core.ipcserver import ipc_server
from prompt_toolkit.formatted_text import HTML
from core.completers import STCompleter
from terminaltables import AsciiTable
from core.utils import print_bad, print_info, print_bad


@register_cli_commands
class Modules(Loader):

    def __init__(self, prompt_session):
        Loader.__init__(self)
        self.type = "module"
        self.paths = ["modules/ipy", "modules/boo"]

        self.name = 'modules'
        self.prompt = HTML('ST (<ansired>modules</ansired>) ≫ ')
        self.completer = STCompleter(self)
        self.prompt_session = prompt_session

        self.selected = None
        self.get_loadables()

    @command
    def list(self, name: str):
        """
        Show available modules

        Usage: list [<name>] [-h]

        Arguments:
            name  filter by module name

        Options:
            -h, --help   Show dis
        """

        table_data = [
            ["Name", "Description"]
        ]
        for m in self.loaded:
            table_data.append([m.name, m.description])

        table = AsciiTable(table_data, title="Modules")
        table.inner_row_border = True
        print(table.table)

    @command
    def run(self, guids: List[str]):
        """
        Run a module

        Usage:
            run <guids>...
            run -h | --help

        Arguments:
            guids    session guids to run modules on

        Options:
            -h, --help   Show dis
        """

        for guid in guids:
            ipc_server.publish(NEW_JOB, (guid, Job(self.selected)))

    @command
    def use(self, name: str):
        """
        Select the specified listener

        Usage: use <name> [-h]

        Arguments:
            name  module name
        """

        for m in self.loaded:
            if m.name == name.lower():
                self.selected = m
                self.prompt_session.message = self.prompt = HTML(f"ST (<ansired>modules</ansired>)(<ansired>{m.name}</ansired>) ≫ ")
                return

        print_bad(f"No module named '{name}'")

    @command
    def options(self):
        """
        Show selected listeners options

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
            print_bad("No module selected")

    @command
    def set(self, name: str, value: str):
        """
        Set options on the selected module

        Usage: set <name> <value> [-h]

        Arguments:
            name   option name
            value  option value
        """

        if self.selected:
            try:
                self.selected.options[name]['Value'] = value
            except KeyError:
                print_bad(f"Unknown option '{name}'")

    @command
    def reload(self):
        """
        Reload all modules

        Usage: reload [-h]

        """

        self.get_loadables()
