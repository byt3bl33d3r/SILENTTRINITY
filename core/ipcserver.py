import logging
import functools
import random
from time import sleep
from secrets import token_bytes
from collections import defaultdict
from multiprocessing.connection import Listener, Client
from threading import Thread


class IPCServer(Thread):
    """
    This is (sort of?) a barebones implementation of a reverse pub/sub
    pattern: multiple publishers can connect to this and it dispatches
    the events to registered subscribers.

    Why? Cause miss me with that zeromq shit.
    """

    def __init__(self, address=('127.0.0.1', random.randint(60000, 65530)), authkey=token_bytes(15)):
        super().__init__()
        self.name = 'IPCServer'
        self.address = address
        self.authkey = authkey
        self.daemon = True
        self.subscribers = defaultdict(set)

    def run(self):
        with Listener(self.address, authkey=self.authkey) as listener:
            logging.debug(f"Started IPC server on {self.address[0]}:{self.address[1]}")
            while True:
                client = listener.accept()

                t = Thread(target=self.wait_for_event, args=(client, listener))
                t.setDaemon(True)
                t.start()

    def attach(self, event, func):
        logging.debug(f"Attaching event: {event} -> {func.__qualname__}")
        self.subscribers[event].add(func)

    def detach(self, event, func):
        raise NotImplementedError

    def publish_event(self, topic, msg):
        if topic in self.subscribers:
            for sub in self.subscribers[topic]:
                return sub(msg)

        """
        with Client(self.address), authkey=self.authkey) as client:
            client.send((topic, msg))
            return client.recv()
        """

    def wait_for_event(self, client, listener):
        logging.debug(f"Connection accepted from {listener.last_accepted[0]}:{listener.last_accepted[1]}")
        while True:
            try:
                data = client.recv()
            except EOFError:
                continue
            else:
                topic, msg = data
                logging.debug(f"Got event: {topic} {f'msg-len: {len(msg)}' if msg else ''}")
                if topic in self.subscribers:
                    for sub in self.subscribers[topic]:
                        client.send(sub(msg))
                else:
                    logging.warning(f"Got event: {topic}, but there's nothing subscribed")
