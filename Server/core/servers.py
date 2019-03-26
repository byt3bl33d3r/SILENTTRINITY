import core.state as state
#import core.events as events
#from core.ipcserver import ipc_server
from prompt_toolkit.formatted_text import HTML
from core.utils import command, register_cli_commands, print_good, print_bad, print_good
from core.completers import STCompleter


@register_cli_commands
class Servers:
    def __init__(self, prompt_session):
        self.servers = []

        self.name = 'servers'
        self.description = 'Servers menu'
        self.prompt = HTML('ST (<ansired>servers</ansired>) ≫ ')
        self.completer = STCompleter(self)
        self.prompt_session = prompt_session

        self.selected = None

    @command
    def host(self, server_type: str, file_path: str):
        """
        Host a file on a server

        Usage:
            host (http|https|webdav|smb) <path_to_file>

        Arguments:
            path_to_file    path of file to host
        """
