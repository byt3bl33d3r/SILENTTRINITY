import asyncio
import logging
from silenttrinity.core.utils import print_good, print_info, print_bad
from silenttrinity.core.client.utils import command, register_cli_commands
from terminaltables import SingleTable
from termcolor import colored
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
                    username = f"{session['info']['Domain']}\\{session['info']['Username']}@{session['info']['Hostname']}"
                    if session['info']['HighIntegrity']:
                        username = f"*{username}"
                except KeyError:
                    username = 'N/A'

                if (gmtime(session['lastcheckin'])[5] > int(session['info']['Sleep']/1000)):
                    timestamp = colored(strftime("%Hh %Mm %Ss", gmtime(session['lastcheckin'])), "red", attrs=['bold'])
                else:
                    timestamp = colored(strftime("%Hh %Mm %Ss", gmtime(session['lastcheckin'])), "green", attrs=['bold'])

                table_data.append([
                    guid,
                    username,
                    session['address'],
                    timestamp
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
    def kill(self, guid: str, response):
        """
        Kill a session

        Usage: kill [-h] <guid>
        """

        print_info(f"Tasked session {guid} to exit")

    @command
    def sleep(self, guid: str, interval: int, response):
        """
        Modify a sessions check-in interval in ms

        Usage: sleep [-h] <guid> <interval>
        """

        #print_good(f"Session {guid} will now check in every {interval}ms")

    @command
    def jitter(self, guid: str, max: int, min: int, response):
        """
        Modify a sessions jitter value in ms

        Usage: jitter [-h] <guid> <max> [<min>]
        """

        #print_good(f"Session {guid} will now have a max jitter of {max}ms and a min jitter of {min}ms")

    @command
    def register(self, guid: str, psk: str, response):
        """
        Register a session with the server

        Usage: register [-h] [<guid>] [<psk>]
        """

        print_good(f"Registered new session (guid: {response.result['guid']} psk: {response.result['psk']})")

    @command
    def checkin(self, guid: str, response):
        """
        Force a session to checkin

        Usage: checkin [-h] <guid>
        """
        pass

    @command
    def rename(self, guid: str, name: str, response):
        """
        Give a session a friendly name

        Usage: rename [-h] <guid> <name>
        """
        pass

    @command
    def unregister(self, guid: str, response):
        """
        Unregister a session with the server. You will need to register the session manually to reuse it again

        Usage: unregister [-h] [<guid>]
        """

        print_good(f"Unregistered session (guid: {response.result['guid']})")
        print_info(f"If you wish to reuse the session you must manually register it")

    @command
    def getpsk(self, guid: str, response):
        """
        Get psk of a session via guid

        Usage: getpsk [-h] [<guid>]
        """

        print_good(f"PSK: {response.result['psk']}")

    @command
    def purge(self, response):
        """
        Purge expired sessions (remove sessions that haven't checked in)

        Usage: purge [-h]
        """

        print_good(f"Purged {response.result['purged']} session(s)")
