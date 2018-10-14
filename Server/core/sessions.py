import functools
import core.state as state
from core.session import Session
from core.job import Job
from time import gmtime, strftime
from queue import Queue, Empty
from prompt_toolkit.formatted_text import HTML
from core.utils import command, register_cli_commands, print_info, print_good, decode_job_response, print_bad
from core.completers import STCompleter
from core.events import NEW_SESSION, SESSION_STAGED, SESSION_CHECKIN, NEW_JOB, JOB_RESULT
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
        self.sessions = []

        self.jobs_queue = {} # Something to storage the job's module.

        ipc_server.attach(NEW_SESSION, self.__add_session)
        ipc_server.attach(SESSION_STAGED, self.__notify_session_staged)
        ipc_server.attach(SESSION_CHECKIN, self.__session_checked_in)
        ipc_server.attach(NEW_JOB, self.__add_job)
        ipc_server.attach(JOB_RESULT, self.__job_result)

    def __add_session(self, session_obj):
        print_good(f"New session {session_obj.guid} connected! ({session_obj.address})")
        # We can't pickle an object with a queue, so we need to add it after we receive it. Ugly.
        session_obj.queue = Queue()
        self.sessions.append(session_obj)
        state.SESSIONS = len(self.sessions)

    def __notify_session_staged(self, msg):
        print_info(msg)

    def __session_checked_in(self, checkin_tuple):
        guid, remote_addr = checkin_tuple
        for session in self.sessions:
            if session.guid == guid:
                session.checked_in()
                try:
                    return session.queue.get(block=False)
                except Empty:
                    return

        print_info(f"Re-attaching orphaned session from {remote_addr} ...")
        self.__add_session(Session(guid, remote_addr, {}))

    def __add_job(self, job_tuple, module_tuple):
        guid, job = job_tuple
        job_id, module = module_tuple

        if guid.lower() == 'all':
            for session in self.sessions:
                session.add_job(job)
                self.add_job_module_queue(session.guid, job_id, module)
            return

        for session in self.sessions:
            if session.guid == guid:
                session.add_job(job)
                self.add_job_module_queue(session.guid, job_id, module)
        return

    def __job_result(self, result):
        guid, data = result
        decoded = decode_job_response(data)
        print_good(f"{guid} returned job result (id: {decoded['id']})")

        self.process_results(guid, decoded)

        # print(decoded['result'])

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
            if session.guid == guid:
                table_data = [["Name", "Value"]]
                for k, v in session.data.items():
                    table_data.append([k.capitalize(), v])
                table = AsciiTable(table_data)
                print(table.table)

    def add_job_module_queue(self, guid, job_id, module):
        if guid not in self.jobs_queue:
            self.jobs_queue[guid] = []
        self.jobs_queue[guid].append((job_id, module))

    def process_results(self, guid, response):
        delete_job = False
        for job in self.jobs_queue[guid]:
            job_id, module = job
            if job_id == response['id']:
                try:
                    module.process(response['result'])
                except Exception as e:
                    print_bad(str(e))
                delete_job = True
                break
        if delete_job:
            self.jobs_queue[guid].remove(job)
