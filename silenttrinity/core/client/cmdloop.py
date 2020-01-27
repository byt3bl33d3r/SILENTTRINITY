import logging
import functools
import shlex
import asyncio
import shutil
from docopt import docopt, DocoptExit
from terminaltables import SingleTable
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import Completer, Completion, PathCompleter
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.application import run_in_terminal
from prompt_toolkit.styles import Style
from prompt_toolkit.document import Document
from silenttrinity.core.client.contexts.teamservers import TeamServers
from silenttrinity.core.client.utils import command, register_cli_commands
from silenttrinity.core.utils import print_bad, print_good, print_info

example_style = Style.from_dict({
    'rprompt': 'bg:#ff0066 #ffffff',
})

def bottom_toolbar(ts):
    if ts.selected and ts.selected.stats.CONNECTED:
        ts = ts.selected
        terminal_width,_ = shutil.get_terminal_size()
        info_bar1 = f"{ts.alias} - {ts.url.scheme}://{ts.url.username}@{ts.url.hostname}:{ts.url.port}"
        info_bar2 = f"[Sessions: {len(ts.stats.SESSIONS)} Listeners: {len(ts.stats.LISTENERS)} Users: {len(ts.stats.USERS)}]"
        ljustify_amount = terminal_width - len(info_bar2)
        return HTML(f"{info_bar1:<{ljustify_amount}}{info_bar2}")
    else:
        return HTML('<b><style bg="ansired">Disconnected</style></b>')

def get_rprompt(error=False):
    return HTML('(<b><ansired>Error</ansired></b>)') if error else ''

class STCompleter(Completer):
    def __init__(self, cli_menu):
        self.path_completer = PathCompleter()
        self.cli_menu = cli_menu

    def get_completions(self, document, complete_event):
        word_before_cursor = document.get_word_before_cursor()
        try:
            cmd_line = list(map(lambda s: s.lower(), shlex.split(document.current_line)))
        except ValueError:
            pass
        else:
            if len(cmd_line):
                if self.cli_menu.current_context.name == 'teamservers':
                    if cmd_line[0] in self.cli_menu.current_context._cmd_registry:
                        for conn in self.cli_menu.current_context.connections:
                            if conn.alias.startswith(word_before_cursor):
                                yield Completion(conn.alias, -len(word_before_cursor))

                if self.cli_menu.teamservers.selected:
                    if cmd_line[0] == 'use':
                        for loadable in self.cli_menu.current_context.available:
                            if word_before_cursor in loadable:
                                # Apperently document.get_word_before_cursor() breaks if there's a forward slash in the command line ?
                                try:
                                    yield Completion(loadable, -len(cmd_line[1]))
                                except IndexError:
                                    yield Completion(loadable, -len(word_before_cursor))
                        return

                    if hasattr(self.cli_menu.current_context, 'selected') and self.cli_menu.current_context.selected:
                        if cmd_line[0] == 'set':
                            if len(cmd_line) >= 2 and cmd_line[1] == 'bindip':
                                for ip in self.cli_menu.teamservers.selected.stats.IPS:
                                    if ip.startswith(word_before_cursor):
                                        yield Completion(ip, -len(word_before_cursor))

                                return

                            for option in self.cli_menu.current_context.selected['options'].keys():
                                if option.lower().startswith(word_before_cursor.lower()):
                                    yield Completion(option, -len(word_before_cursor))
                            return

                        elif cmd_line[0] == 'generate':
                            for listener in self.cli_menu.teamservers.selected.stats.LISTENERS.keys():
                                if listener.startswith(word_before_cursor):
                                    yield Completion(listener, -len(word_before_cursor))

                            return

                        elif cmd_line[0] in ['run', 'info', 'sleep', 'kill', 'jitter', 'checkin', 'rename']:
                            for session in self.cli_menu.teamservers.selected.stats.SESSIONS.values():
                                if session['alias'].startswith(word_before_cursor):
                                    yield Completion(session['alias'], -len(word_before_cursor))

                            return

            if hasattr(self.cli_menu.current_context, "_cmd_registry"):
                for cmd in self.cli_menu.current_context._cmd_registry:
                    if cmd.startswith(word_before_cursor):
                        yield Completion(cmd, -len(word_before_cursor))

            for ctx in self.cli_menu.get_context():
                if ctx.name.startswith(word_before_cursor) and ctx.name is not self.cli_menu.current_context.name:
                    yield Completion(ctx.name, -len(word_before_cursor))

            if self.cli_menu.current_context.name != 'main':
                for cmd in self.cli_menu._cmd_registry:
                    if cmd.startswith(word_before_cursor):
                        yield Completion(cmd, -len(word_before_cursor))

            #https://stackoverflow.com/questions/46528473/how-to-reuse-completions-from-pathcompleter-in-prompt-toolkit
            """
            if word_before_cursor in ['~', './', '/']:
                sub_doc = Document(word_before_cursor)
                yield from (Completion(completion.text, completion.start_position, display=completion.display)
                            for completion
                            in self.path_completer.get_completions(sub_doc , complete_event))
            """

@register_cli_commands
class STShell:
    name = 'main'
    description = 'Main menu'

    _remote = False

    def __init__(self, args):
        self.args = args
        self.current_context = self

        self.teamservers = TeamServers(args['<URL>'])

        self.completer = STCompleter(self)
        self.prompt_session = PromptSession(
            HTML(
                ("[<ansiyellow>"
                 f"{len(self.teamservers.connections)}"
                 "</ansiyellow>] ST ≫ ")
            ),
            bottom_toolbar=functools.partial(bottom_toolbar, ts=self.teamservers),
            completer=self.completer,
            complete_in_thread=True,
            complete_while_typing=True,
            auto_suggest=AutoSuggestFromHistory(),
            #rprompt=get_rprompt(False),
            #style=example_style,
            search_ignore_case=True
        )

    def get_context(self, ctx_name=None):
        try:
            cli_menus = [*self.teamservers.selected.contexts, self.teamservers]
        except AttributeError:
            cli_menus = [self.teamservers]

        if ctx_name:
            return list(filter(lambda c: c.name == ctx_name, cli_menus))[0]
        return cli_menus

    def patch_badchar(self, args, patch=False):
        if patch:
            for key, value in args.items():
                if key == '<value>':
                    args[key] = "-" + value
                    return args
        else:
            try:
                if (args[2][0] == '-'):
                    args[2] = args[2][1:]
                    return True, args
                return False, args
            except IndexError:
                return False, args

    async def update_prompt(self, ctx):
        self.prompt_session.message = HTML(
            ("[<ansiyellow>"
             f"{len(self.teamservers.connections)}"
             f"</ansiyellow>] ST (<ansired>{ctx.name}</ansired>){' ≫ ' if not ctx.prompt else ctx.prompt + ' ≫ ' }")
        )

    async def switched_context(self, text):
        for ctx in self.get_context():
            if text.lower() == ctx.name:
                if ctx._remote is True:
                    try:
                        response = await self.teamservers.send(
                                ctx=ctx.name,
                                cmd="get_selected"
                            )
                        if response.result:
                            ctx.selected = response.result
                    except AttributeError:
                        break

                await self.update_prompt(ctx)
                self.current_context = ctx
                return True
        return False

    async def parse_command_line(self, text):
        if not await self.switched_context(text):
            try:
                command = shlex.split(text)
                logging.debug(f"command: {command[0]} args: {command[1:]} ctx: {self.current_context.name}")
                needs_patch, command = self.patch_badchar(command)

                args = docopt(
                    getattr(self.current_context if hasattr(self.current_context, command[0]) else self, command[0]).__doc__,
                    argv=command[1:]
                )

                if needs_patch:
                    args = self.patch_badchar(args, patch=True)
            except ValueError as e:
                print_bad(f"Error parsing command: {e}")
            except AttributeError as e:
                print_bad(f"Unknown command '{command[0]}'")
            except (DocoptExit, SystemExit):
                pass
            else:
                if command[0] in self._cmd_registry or self.current_context._remote is False:
                    run_in_terminal(
                        functools.partial(
                            getattr(self if command[0] in self._cmd_registry else self.current_context, command[0]),
                            args=args
                        )
                    )

                elif self.current_context._remote is True:
                    response = await self.teamservers.send(
                            ctx=self.current_context.name,
                            cmd=command[0],
                            args=args
                        )

                    logging.debug(f"response: {response}")

                    if response.status == 'success' and response.result:
                        if hasattr(self.current_context, command[0]):
                            run_in_terminal(
                                functools.partial(
                                    getattr(self.current_context, command[0]),
                                    args=args,
                                    response=response
                                )
                            )

                    elif response.status == 'error':
                        print_bad(response.result)

                if self.current_context.name != 'main':
                    await self.update_prompt(self.current_context)

    async def run_resource_file(self, rc_file):
        with open(rc_file) as resource_file:
            for cmd in resource_file:
                with patch_stdout():
                    try:
                        text = await self.prompt_session.prompt_async(accept_default=True, default=cmd.strip())
                    except AssertionError:
                        text = cmd.strip()
                    await self.parse_command_line(text)

    async def cmdloop(self):
        if self.args['--resource-file']:
            if self.teamservers.selected:
                # We sleep for one second to allow for the connection to complete
                # As of writing there isn't a way to wait until the initial connection is successfull
                #e.g. await self.teamservers.selected.connected
                await asyncio.sleep(1)
                await self.run_resource_file(self.args['--resource-file'])

        while True:
            with patch_stdout():
                text = await self.prompt_session.prompt_async()
                if len(text):
                    if text.lower() == 'exit':
                        break

                    await self.parse_command_line(text)

    @command
    def help(self):
        """
        Shows available commands

        Usage: help

        """
        table_data = [
            ["Command", "Description"]
        ]

        try:
            for cmd in self.current_context._cmd_registry:
                table_data.append([cmd, getattr(self.current_context, cmd).__doc__.split('\n', 2)[1].strip()])

            for menu in self.get_context():
                if menu.name != self.current_context.name:
                    table_data.append([menu.name, menu.description])
        except AttributeError:
            for menu in self.get_context():
                table_data.append([menu.name, menu.description])

        table = SingleTable(table_data)
        print(table.table)

    @command
    def runrcfile(self, rc_file: str):
        """
        Runs a resource file

        Usage: runrcfile [-h] <rc_file>
        """

        if rc_file:
            asyncio.create_task(self.run_resource_file(rc_file))
