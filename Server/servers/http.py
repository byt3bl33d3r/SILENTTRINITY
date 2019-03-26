import asyncio
from core.server import Server
from quart import Quart, Blueprint, request, Response
#from quart.logging import default_handler, serving_handler
from hypercorn import Config
from hypercorn.asyncio import serve


class STServer(Server):
    def __init__(self):
        Server.__init__(self)
        self.name = 'http'
        self.app = None
        self.bind_ip = None
        self.port = None

    def run(self, bind_ip, port):
        self.bind_ip = bind_ip
        self.port = int(port)

        config = Config()
        config.host = self.bind_ip
        config.port = self.port
        config.debug = False
        config.use_reloader = False

        self.app = Quart(__name__)
        asyncio.run(serve(self.app, config))
