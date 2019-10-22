import asyncio
import logging
from typing import List
from silenttrinity.core.client.utils import command, register_cli_commands
from terminaltables import SingleTable
from time import gmtime, strftime

@register_cli_commands
class Modules:
    name = 'modules'
    description = 'Modules menu'

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
        Select the specified module

        Usage: use <name> [-h]

        Arguments:
            name  module to select
        """

        self.selected = response.result

    @command
    def list(self, name: str, response):
        """
        Get available modules

        Usage: list [-h] [<name>]

        Arguments:
            name   filter by module name
        """

        table_data = [['Name', 'Description']]
        for m_name, m_description in response.result.items():
            table_data.append([m_name, m_description])

        table = SingleTable(table_data, title="Modules")
        table.inner_row_border = True
        print(table.table)

    @command
    def options(self, response):
        """
        Show selected module options

        Usage: options [-h]
        """

        table_data = [["Option Name", "Required", "Value", "Description"]]
        for k, v in response.result.items():
            table_data.append([k, v["Required"], v["Value"], v["Description"]])

        table = SingleTable(table_data, title=self.selected['name'])
        table.inner_row_border = True
        print(table.table)

    @command
    def info(self, response):
        """
        Show detailed information of the selected module

        Usage: options [-h]
        """
        print(f"Author(s): {response.result['author']}")
        print(f"Description: {response.result['description']}")
        print(f"Language: {response.result['language']}\n")

        table_data = [["Option Name", "Required", "Value", "Description"]]
        for k, v in response.result['options'].items():
            table_data.append([k, v["Required"], v["Value"], v["Description"]])

        table = SingleTable(table_data, title=self.selected['name'])
        table.inner_row_border = True
        print(table.table)

    @command
    def run(self, guids: List[str], response):
        """
        Run a module

        Usage:
            run <guids>...
            run -h | --help

        Arguments:
            guids    session guids to run modules on 
                     (specifying 'all' will run module on all sessions)

        Options:
            -h, --help   Show dis
        """
        pass

    @command
    def reload(self, response):
        """
        Reload all modules

        Usage: reload [-h]
        """
        pass

    @command
    def set(self, name: str, value: str, response):
        """
        Set options on the selected module

        Usage: set <name> <value> [-h]

        Arguments:
            name   option name
            value  option value
        """
