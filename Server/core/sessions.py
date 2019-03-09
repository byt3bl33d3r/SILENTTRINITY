import logging
import json
import core.state as state
import core.events as events
from core.module import Module
from core.session import Session
from core.job import Job
from time import gmtime, strftime
from prompt_toolkit.formatted_text import HTML
from core.utils import command, register_cli_commands, print_info, print_good
from core.completers import STCompleter
from core.ipcserver import ipc_server
from terminaltables import AsciiTable


@register_cli_commands
class Sessions:
    def __init__(self, prompt_session):
        self.name = 'sessions'
        self.description = 'Session menu'
        self.prompt = HTML('ST (<ansired>sessions</ansired>) ≫ ')
        self.completer = STCompleter(self)
        self.prompt_session = prompt_session

        self.selected = None
        self.sessions = set()

        self.jobs_modules: dict = {}

        """
        The following code sucks.

        We can probably pull some really fancy stuff here like registring functions 
        using decorators in each Session object so when an event is published
        it gets routed directly to the right session with the appropriate GUID.
        This would be ideal as it would remove almost all of these helper functions.

        I've tried doing this but it resulted in me drinking a lot with very little success.
        """

        ipc_server.attach(events.KEX, self.kex)
        ipc_server.attach(events.ENCRYPT_STAGE, self.gen_encrypted_stage)
        ipc_server.attach(events.SESSION_STAGED, self.notify_session_staged)
        ipc_server.attach(events.SESSION_CHECKIN, self.session_checked_in)
        ipc_server.attach(events.NEW_JOB, self.add_job)
        ipc_server.attach(events.JOB_RESULT, self.job_result)

    def kex(self, kex_tuple):
        guid, remote_addr, pubkey_xml = kex_tuple
        try:
            session = list(filter(lambda x: x == guid, self.sessions))[0]
            logging.debug(f"creating new pub/priv keys for {guid}")
            session.set_peer_public_key(pubkey_xml)
        except IndexError:
            logging.debug(f"new kex from {remote_addr} ({guid})")
            session = Session(guid, remote_addr, pubkey_xml)
            self.sessions.add(session)

        return session.public_key

    def gen_encrypted_stage(self, info_tuple):
        guid, remote_addr = info_tuple
        session = list(filter(lambda x: x == guid, self.sessions))[0]
        return session.get_encrypted_stage()

    def notify_session_staged(self, msg):
        print_info(msg)

    def session_checked_in(self, checkin_tuple):
        guid, remote_addr = checkin_tuple
        session = list(filter(lambda x: x == guid, self.sessions))[0]
        session.checked_in()

        return session.get_job()

    def add_job(self, job_tuple):
        guid, job = job_tuple

        self.add_job_module(job)

        if guid.lower() == 'all':
            for session in self.sessions:
                session.add_job(job)
        else:
            for session in self.sessions:
                if session == guid:
                    session.add_job(job)

    def job_result(self, result_tuple):
        guid, job_id, data = result_tuple
        session = list(filter(lambda x: x == guid, self.sessions))[0]

        if not session.data:
            session.set_session_info(data)
            print_good(f"New session {session.guid} connected! ({session.address})")
            state.SESSIONS = len(self.sessions)
            return

        for session in self.sessions:
            if session == guid:
                results = json.loads(session.crypto.decrypt(data))
                print_good(f"{guid} returned job result (id: {job_id})")
                self.get_job_module(job_id).process(results['result'])

    def add_job_module(self, job: Job) -> None:
        self.jobs_modules[job.id] = job.module

    def get_job_module(self, job_id: str) -> Module:
        return self.jobs_modules.pop(job_id)

    @command
    def sleep(self, guid: str, interval: int):
        """
        Set the checkin interval for an agent

        Usage: sleep <guid> <interval> [-h]

        Arguments:
            guid  filter by session's guid
            interval  checkin interval in milliseconds
        """

        for session in self.sessions:
            if session == guid:
                session.add_job(Job(command=('sleep', int(interval))))

    @command
    def list(self, guid: str):
        """
        Get available sessions

        Usage: list [<guid>] [-h]

        Arguments:
            guid  filter by session's guid
        """

        table_data = [
            ["GUID", "User", "Address", "Last Checkin"]
        ]

        for session in self.sessions:
            if session.data:
                try:
                    username = f"*{session.data['username']}@{session.data['domain']}" if session.data['high_integrity'] else f"{session.data['username']}@{session.data['domain']}"
                except KeyError:
                    username = ''

                table_data.append([
                    session.guid,
                    username,
                    session.address,
                    strftime("h %H m %M s %S", gmtime(session.last_check_in()))
                ])

        table = AsciiTable(table_data)
        print(table.table)

    @command
    def info(self, guid: str):
        """
        Get session info

        Usage: info <guid> [-h]

        Arguments:
            guid  filter by session's guid
        """

        for session in self.sessions:
            if session == guid:
                table_data = [["Name", "Value"]]
                for k, v in session.data.items():
                    table_data.append([k, v])
                table = AsciiTable(table_data)
                print(table.table)
