import asyncio
import logging
from terminaltables import SingleTable
from silenttrinity.core.utils import print_good
from silenttrinity.core.client.utils import command, register_cli_commands

@register_cli_commands
class Stagers:
    name = 'stagers'
    description = 'Stagers menu'

    _remote = True

    def __init__(self):
        self.prompt = None
        self.available = []
        self._selected = None

    @property
    def selected(self):
        return self._selected

    @selected.setter
    def selected(self, data):
        self.prompt = f"(<ansired>{data['name']}</ansired>)"
        self._selected = data

    @command
    def use(self, name: str, response):
        """
        Select the specified stager

        Usage: use <name> [-h]

        Arguments:
            name  filter by stager name
        """

        self.selected = response.result

    @command
    def list(self, response):
        """
        List available stagers

        Usage: list [-h]
        """
        table_data = [
            ["Name", "Description"]
        ]
        for name,fields in response.result.items():
            table_data.append([name, fields["description"]])

        table = SingleTable(table_data, title="Available")
        table.inner_row_border = True
        print(table.table)

    @command
    def options(self, response):
        """
        Show selected stager options

        Usage: options [-h]
        """

        table_data = [
            ["Option Name", "Required", "Value", "Description"]
        ]

        for k, v in response.result.items():
            table_data.append([k, v["Required"], v["Value"], v["Description"]])

        table = SingleTable(table_data, title="Stager Options")
        table.inner_row_border = True
        print(table.table)

    @command
    def generate(self, listener_name: str, response):
        """
        Generate the selected stager

        Usage: generate [-h] <listener_name> 
        
        Arguments:
            listener_name   listener name
        """

        generated_stager = response.result

        stager_filename = f"./stager.{generated_stager['extension']}"
        with open(stager_filename, 'wb') as stager:
            stager.write(generated_stager['output'].encode('latin-1'))

        print_good(f"Generated stager to {stager_filename}")

    @command
    def set(self, name: str, value: str, response):
        """
        Set options on the selected listener

        Usage: set <name> <value> [-h]

        Arguments:
            name   option name
            value  option value
        """

    @command
    def reload(self, response):
        """
        Reload all modules

        Usage: reload [-h]
        """
