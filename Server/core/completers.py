from prompt_toolkit.completion import Completer, Completion
from core.utils import get_ips
from shlex import split


class STCompleter(Completer):

    def __init__(self, cli_menu):
        self.cli_menu = cli_menu

    def get_completions(self, document, complete_event):
        word_before_cursor = document.get_word_before_cursor()

        # This can't be the best way of doing this, just can't seem to find the right method on the document object
        if len(split(document.current_line)):

            if split(document.current_line)[0].lower() == 'use':
                for module in self.cli_menu.loaded:
                    if module.name.startswith(word_before_cursor):
                        yield Completion(module.name, -len(word_before_cursor))

                return

            elif self.cli_menu.selected and split(document.current_line)[0].lower() == 'set':
                if len(split(document.current_line)) >= 2 and split(document.current_line)[1].lower() == 'bindip':
                    for ip in get_ips():
                        if ip.startswith(word_before_cursor):
                            yield Completion(ip, -len(word_before_cursor))

                    return

                for k in self.cli_menu.selected.options.keys():
                    if k.startswith(word_before_cursor):
                        yield Completion(k, -len(word_before_cursor))

                return

            elif self.cli_menu.selected and split(document.current_line)[0].lower() == 'generate':
                for listener in self.cli_menu.prompt_session.contexts[0].listeners:
                    if listener.name.startswith(word_before_cursor):
                        yield Completion(listener.name, -len(word_before_cursor))

                return

            elif split(document.current_line)[0].lower() in ['run', 'info', 'sleep']:
                for session in self.cli_menu.prompt_session.contexts[1].sessions:
                    if str(session.guid).startswith(word_before_cursor):
                        yield Completion(str(session.guid), -len(word_before_cursor))

                return

        for ctx in self.cli_menu.prompt_session.contexts:
            if ctx.name.startswith(word_before_cursor) and ctx.name is not self.cli_menu.name:
                yield Completion(ctx.name, -len(word_before_cursor))

        for cmd in self.cli_menu._cmd_registry:
            if cmd.startswith(word_before_cursor):
                yield Completion(cmd, -len(word_before_cursor))
