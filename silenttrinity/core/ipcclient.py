import logging
import sys
import traceback
from silenttrinity.core.events import Events
from silenttrinity.core.teamserver import ipc_server
from collections import defaultdict
from multiprocessing import Process, Pipe
from multiprocessing.connection import Client


class IPCException(Exception):
    pass


class IPCClient:

    def __init__(self):
        self.subscribers = defaultdict(set)
        self.conn = None
        self.thread = None

    @property
    def running(self):
        if self.thread:
            return self.thread.is_alive()
        return False

    def run(self):
        return

    def start_in_seperate_process(self, pipe):
        self.conn = Client(ipc_server.address, authkey=ipc_server.authkey)
        try:
            self.run()
        except Exception:
            self.conn.close()
            #Cause traceback objects aren't pickle'able, whytho.jpg
            pipe.send("".join(traceback.format_exception(*sys.exc_info())))

    def attach(self, event, func):
        self.subscribers[event].add(func)

    def start(self):
        recv_pipe, send_pipe = Pipe()
        self.thread = Process(target=self.start_in_seperate_process, daemon=True, args=(send_pipe,))
        self.thread.start()

        try:
            if recv_pipe.poll(0.5):
                exc_info = recv_pipe.recv()
                logging.error(f'Error starting process, got exception:\n{exc_info}')
                self.thread.join()
                raise Exception(exc_info.splitlines()[-1])
        finally:
            recv_pipe.close()
            send_pipe.close()

    def dispatch_event(self, event, msg):
        self.conn.send((event, msg))
        try:
            topic, data = self.conn.recv()
            if topic == Events.EXCEPTION:
                logging.debug(f"Received data back from event: {event} - ERROR - {data}")
                raise Exception(data)

            logging.debug(f"Received data back from event: {event} - OK")
            return data
        except EOFError:
            pass

    def stop(self):
        self.thread.kill()
        self.thread.join()
        logging.debug(f"Stopping process pid: {self.thread.pid}, name:{self.thread.name}/{self.thread.ident}")
