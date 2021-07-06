import os
import logging
import asyncio
import uuid
from termcolor import colored
from silenttrinity.core.events import Events
from silenttrinity.core.utils import gen_random_string, CmdError
from silenttrinity.core.teamserver import ipc_server
from silenttrinity.core.teamserver.db import STDatabase
from silenttrinity.core.teamserver.crypto import gen_stager_psk
from silenttrinity.core.teamserver.session import Session, SessionNotFoundError
from silenttrinity.core.teamserver.job import Job
from time import gmtime, strftime
#from core.teamserver.utils import subscribe, register_subscriptions

"""
The following code sucks.

We can probably pull some really fancy stuff here like registering functions 
using decorators in each Session object so when an event is published
it gets routed directly to the right session with the appropriate GUID.
This would be ideal as it would remove almost all of these helper functions.

I've tried doing this, but it resulted in me drinking a lot with very little success.
"""

#@register_subscriptions
class Sessions:
    name = 'sessions'
    description = 'Sessions menu'

    def __init__(self, teamserver):
        self.teamserver = teamserver
        self.selected = None
        self.sessions = set()

        ipc_server.attach(Events.KEX, self.kex)
        ipc_server.attach(Events.ENCRYPT_STAGE, self.gen_encrypted_stage)
        ipc_server.attach(Events.SESSION_STAGED, self.notify_session_staged)
        ipc_server.attach(Events.SESSION_REGISTER, self._register)
        ipc_server.attach(Events.SESSION_CHECKIN, self.session_checked_in)
        ipc_server.attach(Events.NEW_JOB, self.add_job)
        ipc_server.attach(Events.JOB_RESULT, self.job_result)

        with STDatabase() as db:
            for registered_session in db.get_sessions():
                _, guid, psk = registered_session
                self._register(guid, psk)

    def get_session(self, guid, attempt_auto_reg=True):
        try:
            return list(filter(lambda x: x == guid, self.sessions))[0]
        except IndexError:
            logging.error(f"Tried to lookup non registered session {guid}")
            if attempt_auto_reg:
                logging.info("Attempting automatic registration from database")
                with STDatabase() as db:
                    psk = db.get_session_psk(guid)
                    if psk:
                        self._register(guid, psk)
                        logging.info("Automatic registration successful")
                        return self.get_session(guid)
                logging.error(f"Could not automatically register session {guid}, PSK not in database")
                logging.warning(colored("This could be an orphaned session or somebody could be messing with the teamserver!", "red"))

            raise SessionNotFoundError(f"Session with guid {guid} was not found")

    def guid_is_valid(self, guid):
        try:
            uuid.UUID(str(guid))
        except ValueError:
            raise CmdError("Invalid Guid")

    def _register(self, guid, psk):
        session = Session(guid, psk)
        self.sessions.add(session)
        with STDatabase() as db:
            db.add_session(guid, psk)
        logging.info(f"Registering session: {session}")

    def register(self, guid, psk):
        if not guid:
            guid = uuid.uuid4()
        if not psk:
            psk = gen_stager_psk()

        self.guid_is_valid(guid)

        self._register(guid, psk)
        return {"guid": str(guid), "psk": psk}

    #@subscribe(events.KEX)
    def kex(self, kex_tuple):
        guid, remote_addr, enc_pubkey = kex_tuple
        try:
            session = self.get_session(guid)
            logging.debug(f"Creating new shared secret with {guid}")
            session.crypto.derive_shared_key(enc_pubkey)
            return session.crypto.enc_public_key
        except SessionNotFoundError:
            logging.error(f"Got kex request from {remote_addr} but no sessions registered with guid {guid}")
            raise

    #@subscribe(events.ENCRYPT_STAGE)
    def gen_encrypted_stage(self, info_tuple):
        guid, remote_addr, comms = info_tuple
        try:
            session = self.get_session(guid)
            return session.gen_encrypted_stage(comms.split(','))
        except SessionNotFoundError:
            logging.error(f"Got staging request from {remote_addr} but no sessions registered with guid {guid}")
            raise

    #@subscribe(events.SESSION_CHECKIN)
    def session_checked_in(self, checkin_tuple):
        guid, remote_addr = checkin_tuple
        try:
            session = self.get_session(guid)
            session.address = remote_addr
            session.checked_in()
            return session.jobs.get()
        except SessionNotFoundError:
            logging.error(f"Got checkin request from {remote_addr} but no sessions registered with guid {guid}")
            raise

    #@subscribe(events.NEW_JOB)
    def add_job(self, guid, job):
        if guid.lower() == 'all':
            for session in self.sessions:
                session.jobs.add(job)
        else:
            try:
                session = self.get_session(guid, attempt_auto_reg=False)
                session.jobs.add(job)
            except SessionNotFoundError:
                logging.error(f"No session was found with name: {guid}")

    #@subscribe(events.JOB_RESULT)
    def job_result(self, result_tuple):
        guid, remote_addr, job_id, data = result_tuple
        try:
            session = self.get_session(guid)
        except SessionNotFoundError:
            logging.error(f"Got job results from {remote_addr} but no sessions registered with guid {guid}")
            raise
        else:
            decrypted_job, job_output = session.jobs.decrypt(job_id, data)

            if decrypted_job['cmd'] == 'CheckIn':
                if not session.info:
                    session.info = job_output
                    logging.debug(f"New session {session.guid} connected! ({session.address})")

                    #Since these methods get called from a seperate OS thread in ipc_server, we must use asyncio.run_coroutine_threadsafe()
                    asyncio.run_coroutine_threadsafe(
                            self.teamserver.users.broadcast_event(
                                Events.NEW_SESSION, 
                                f"New session {session.guid} connected! ({session.address})"
                        ),
                        loop=self.teamserver.loop
                    )

                    asyncio.run_coroutine_threadsafe(
                        self.teamserver.update_server_stats(),
                        loop=self.teamserver.loop
                    )
                else:
                    session.info = job_output
                    asyncio.run_coroutine_threadsafe(
                            self.teamserver.users.broadcast_event(
                                Events.JOB_RESULT, 
                                {'id': job_id, 'output': 'Reporting for duty comrade! ☭', 'session': session.guid, 'address': session.address}
                        ),
                        loop=self.teamserver.loop
                    )
            else:
                logging.debug(f"{session.guid} returned job/command result (id: {job_id})")

                asyncio.run_coroutine_threadsafe(
                        self.teamserver.users.broadcast_event(
                            Events.JOB_RESULT, 
                            {'id': job_id, 'output': job_output, 'session': session.guid, 'address': session.address}
                    ),
                    loop=self.teamserver.loop
                )

    #@subscribe(events.SESSION_STAGED)
    def notify_session_staged(self, msg):
        #Since these methods get called from a seperate OS thread in ipc_server, we must use asyncio.run_coroutine_threadsafe()
        asyncio.run_coroutine_threadsafe(
                self.teamserver.users.broadcast_event(
                    Events.SESSION_STAGED, 
                    msg
            ),
            loop=self.teamserver.loop
        )

    def list(self):
        return {s.name: dict(s) for s in self.sessions if s.info}

    def info(self, guid):
        try:
            return dict(self.get_session(guid))
        except SessionNotFoundError:
            raise CmdError(f"No session named: {guid}")

    def kill(self, guid):
        try:
            session = self.get_session(guid)
            session.jobs.add(Job(command=('Exit', [])))
            return {'guid': guid, 'status': 'Tasked to exit'}
        except SessionNotFoundError:
            raise CmdError(f"No session named: {guid}")

    def sleep(self, guid, interval):
        try:
            session = self.get_session(guid)
            session.jobs.add(Job(command=('Sleep', [int(interval)])))
        except SessionNotFoundError:
            raise CmdError(f"No session named: {guid}")

    def jitter(self, guid, max, min):
        try:
            session = self.get_session(guid)
            if min:
                session.jobs.add(Job(command=('Jitter', [int(max), int(min)])))
            else:
                session.jobs.add(Job(command=('Jitter', [int(max)])))
        except SessionNotFoundError:
            raise CmdError(f"No session named: {guid}")

    def checkin(self, guid):
        try:
            session = self.get_session(guid)
            session.jobs.add(Job(command=('CheckIn', [])))
        except SessionNotFoundError:
            raise CmdError(f"No session named: {guid}")

    def rename(self, guid, name):
        try:
            session = self.get_session(guid)
            session.name = name
        except SessionNotFoundError:
            raise CmdError(f"No session with guid: {guid}")

    def unregister(self, guid):
        self.guid_is_valid(guid)

        if guid in self.sessions:
            raise CmdError("You can't unregister an active session. Kill then purge the session first.")

        with STDatabase() as db:
            db.remove_session(guid)

        logging.info(f"Unregistering session: {guid}")

        return {"guid": str(guid)}

    def getpsk(self, guid):
        self.guid_is_valid(guid)

        with STDatabase() as db:
            psk = db.get_session_psk(guid)
            return {"psk": psk}

    def purge(self):
        counter = 0
        s = {s.guid: dict(s) for s in self.sessions if s.info}
        for guid, session in s.items():
            if session['info']:
                if (gmtime(session['lastcheckin'])[5] > int(session['info']['Sleep']/1000)):
                    self.sessions.remove(guid)
                    counter += 1

        return {'purged': counter}

    def __iter__(self):
        for session in self.sessions:
            if session.info:
                yield (str(session._guid), dict(session))

    def __str__(self):
        return self.__class__.__name__.lower()
