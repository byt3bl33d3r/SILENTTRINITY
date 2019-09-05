import asyncio
import logging
from core.utils import print_good
from core.client.utils import command, register_cli_commands
from terminaltables import SingleTable
from time import gmtime, strftime

@register_cli_commands
class Sessions:
    name = 'sessions'
    description = 'Sessions menu'

    _remote = True

    def __init__(self):
        self._selected = None
        self.prompt = None

    @property
    def selected(self):
        return self._selected

    @selected.setter
    def selected(self, data):
        #self.prompt = f"(<ansired>{data['name']}</ansired>)"
        self._selected = data

    @command
    def list(self, response):
        """
        Get available sessions

        Usage: list [-h]
        """

        table_data = [
            ["Name", "User", "Address", "Last Checkin"]
        ]

        for guid,session in response.result.items():
            if session['info']:
                try:
                    username = f"*{session['info']['Username']}@{session['info']['Domain']}" if session['info']['HighIntegrity'] else f"{session['info']['Username']}@{session['info']['Domain']}"
                except KeyError:
                    username = ''

                table_data.append([
                    guid,
                    username,
                    session['address'],
                    strftime("h %H m %M s %S", gmtime(session['lastcheckin']))
                ])

        table = SingleTable(table_data, title="Sessions")
        table.inner_row_border = True
        print(table.table)

    @command
    def info(self, guid: str, response):
        """
        Get info of a specified session

        Usage: info [-h] <guid>
        """

        table_data = [["Name", "Value"]]
        for k,v in response.result['info'].items():
            table_data.append([k, v])

        table = SingleTable(table_data, title="Session Info")
        table.inner_row_border = True
        print(table.table)

    @command
    def register(self, guid: str, psk: str, response):
        """
        Register a session with the server

        Usage: register [-h] [<guid>] [<psk>]
        """

        print_good(f"Registered new session (guid: {response.result['guid']} psk: {response.result['psk']})")
