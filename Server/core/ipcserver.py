import logging
import functools
import asyncio
from time import sleep
from prompt_toolkit.application import run_in_terminal
from multiprocessing.connection import Listener
from threading import Thread


class IPCServer(Thread):
    """
    This is (sort of?) a barebones implementation of a reverse pub/sub
    pattern: multiple publishers can connect to this and it dispatches
    the events to registered subscribers.

    Why? Cause miss me with that zeromq shit.
    """

    def __init__(self, address=('localhost', 60000), authkey=b'silenttrinity'):
        Thread.__init__(self)
        self.name = 'IPCServer'
        self.address = address
        self.listener = Listener(self.address, authkey=authkey)
        self.daemon = True
        self.subscribers = {}

    def run(self):
        logging.debug(f"Started IPC server on {self.address}")
        while True:
            client = self.listener.accept()

            t = Thread(target=self.serve, args=(client,))
            t.setDaemon(True)
            t.start()

    def attach(self, event, func):
        if event not in self.subscribers:
            self.subscribers[event] = set()
            self.subscribers[event].add(func)
        else:
            self.subscribers[event].add(func)

    def detach(self, event, func):
        raise NotImplemented

    def publish(self, topic, msg):
        if topic in self.subscribers:
            for sub in self.subscribers[topic]:
                #run_in_terminal(functools.partial(sub, msg))
                return sub(msg)

    def serve(self, client):
        logging.debug(f"connection accepted from {self.listener.last_accepted}")
        while True:
            try:
                data = client.recv()
            except EOFError:
                pass

            topic, msg = data
            logging.debug(f"Got event: {topic} msg: {msg}")
            if topic in self.subscribers:
                for sub in self.subscribers[topic]:
                    future = run_in_terminal(functools.partial(sub, msg))
                    future.add_done_callback(functools.partial(lambda f, c: c.send(f.result()), c=client))
            else:
                logging.debug(f"Got event: {topic}, but there's nothing subscribed")


ipc_server = IPCServer()
ipc_server.start()
