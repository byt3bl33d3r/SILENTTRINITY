import logging
from core.teamserver import ipc_server
from collections import defaultdict
from multiprocessing import Process
from multiprocessing.connection import Client
from threading import Thread

class IPCClient:

    def __init__(self):
        self.running = False
        self.subscribers = defaultdict(set)
        self.__conn = None
        self.__thread = None

    def run(self):
        return

    def __run(self):
        self.__conn = Client(ipc_server.address, authkey=ipc_server.authkey)
        self.run()

    def attach(self, event, func):
        self.subscribers[event].add(func)

    def start(self):
        self.__thread = Process(target=self.__run, daemon=True)
        self.__thread.start()
        self.running = True

    def dispatch_event(self, event, msg):
        self.__conn.send((event, msg))
        try:
            data = self.__conn.recv()
            logging.debug(f"Received data back from event: {event} data: {data}")
            return data
        except EOFError:
            pass

    def stop(self):
        self.__thread.kill()
        logging.debug(f"Stopping process pid: {self.__thread.pid}, name:{self.__thread.name}/{self.__thread.ident}")
        self.running = False
