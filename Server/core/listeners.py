import core.state as state
from core.events import GET_LISTENERS
from core.ipcserver import ipc_server
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.completion import WordCompleter
from core.utils import command, print_good, print_bad, print_good
from core.loader import Loader
from terminaltables import AsciiTable
from copy import deepcopy


class Listeners(Loader):
    def __init__(self, prompt_session):
        Loader.__init__(self)
        self.type = "listener"
        self.paths = ["listeners/"]
        self.listeners = []

        self.name = 'listeners'
        self.prompt = HTML('ST (<ansired>listeners</ansired>) ≫ ')
        self.completer = WordCompleter(['start', 'set', 'sessions', 'modules', 'stagers', 'options', 'use', 'exit', 'list'], ignore_case=True)
        self.prompt_session = prompt_session

        self.selected = None

        ipc_server.attach(GET_LISTENERS, self.__get_running_listeners)

        self.get_loadables()

    def __get_running_listeners(self, msg):
        return self.listeners

    @command
    def list(self, name: str, running: bool, available: bool):
        """
        Get running/available listeners

        Usage: list [<name>] [--running] [--available] [-h]

        Arguments:
            name  filter by listener name

        Options:
            -h, --help        Show dis
            -r, --running     List running listeners
            -a, --available   List available listeners
        """

        table_data = [
            ["Name", "Description"]
        ]
        for l in self.loaded:
            table_data.append([l.name, l.description])

        table = AsciiTable(table_data, title="Available")
        table.inner_row_border = True
        print(table.table)

        table_data = [
            ["Type", "Name", "URL"]
        ]
        for l in self.listeners:
            table_data.append([l.name, l["Name"], f"https://{l['BindIP']}:{l['Port']}"])

        table = AsciiTable(table_data, title="Running")
        table.inner_row_border = True
        print(table.table)

    @command
    def use(self, name: str):
        """
        Select the specified listener

        Usage: use <name> [-h]

        Arguments:
            name  filter by listener name
        """

        for l in self.loaded:
            if l.name == name.lower():
                self.selected = deepcopy(l)

                new_prompt = HTML(f"ST (<ansired>listeners</ansired>)(<ansired>{l.name}</ansired>) ≫ ")
                self.prompt_session.message = new_prompt
                self.prompt = new_prompt

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
            print_bad("No listener selected")

    @command
    def start(self):
        """
        Start the selected listener

        Usage: start [-h]
        """

        try:
            self.selected.start()
            self.listeners.append(self.selected)
            print_good(f"Listener '{self.selected['Name']}' started successfully!")
            state.LISTENERS = len(self.listeners)
        except Exception as e:
            print_bad(f"Error starting listener '{self.selected['Name']}': {e}")

    @command
    def set(self, name: str, value: str):
        """
        Set options on the selected listener

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
