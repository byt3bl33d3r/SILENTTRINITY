import logging
import core.state as state
import core.events as events
from core.session import Session
from time import gmtime, strftime
from prompt_toolkit.formatted_text import HTML
from core.utils import command, register_cli_commands, print_info, print_good, subscribe
from core.completers import STCompleter
from core.ipcserver import ipc_server
from terminaltables import AsciiTable


@register_cli_commands
class Sessions:
    def __init__(self, prompt_session):
        self.name = 'sessions'
        self.prompt = HTML('ST (<ansired>sessions</ansired>) ≫ ')
        self.completer = STCompleter(self)
        self.prompt_session = prompt_session

        self.selected = None
        self.sessions = set()

        ipc_server.attach(events.KEX, self.__kex)
        ipc_server.attach(events.ENCRYPT_STAGE, self.__gen_encrypted_stage)
        ipc_server.attach(events.SESSION_STAGED, self.__notify_session_staged)
        ipc_server.attach(events.SESSION_CHECKIN, self.__session_checked_in)
        ipc_server.attach(events.NEW_JOB, self.__add_job)
        ipc_server.attach(events.JOB_RESULT, self.__job_result)


    #@subscribe(events.KEX)
    def __kex(self, kex_tuple):
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

    #@subscribe(events.ENCRYPT_STAGE)
    def __gen_encrypted_stage(self, info_tuple):
        guid, remote_addr = info_tuple
        session = list(filter(lambda x: x == guid, self.sessions))[0]
        return session.get_encrypted_stage()

    #@subscribe(events.SESSION_STAGED)
    def __notify_session_staged(self, msg):
        print_info(msg)

    #@subscribe(events.SESSION_CHECKIN)
    def __session_checked_in(self, checkin_tuple):
        guid, remote_addr = checkin_tuple
        session = list(filter(lambda x: x == guid, self.sessions))[0]
        session.checked_in()

        return session.get_job()

    #@subscribe(events.NEW_JOB)
    def __add_job(self, job_tuple):
        guid, job = job_tuple
        if guid.lower() == 'all':
            for session in self.sessions:
                session.add_job(job)
        else:
            for session in self.sessions:
                if session == guid:
                    session.add_job(job)

    #@subscribe(events.JOB_RESULT)
    def __job_result(self, result_tuple):
        guid, job_id, data = result_tuple
        session = list(filter(lambda x: x == guid, self.sessions))[0]

        if not session.data:
            session.set_session_info(data)
            print_good(f"New session {session.guid} connected! ({session.address})")
            state.SESSIONS = len(self.sessions)
            return

        for session in self.sessions:
            if session == guid:
                results = session.crypto.decrypt(data)
                print_good(f"{guid} returned job result (id: {job_id})")
                print(results)

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
