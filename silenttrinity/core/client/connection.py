import asyncio
import websockets
import hmac
import ssl
import logging
import pathlib
import json
import functools
from urllib.parse import urlparse
from base64 import b64encode
from websockets.http import Headers
from hashlib import sha512
from silenttrinity.core.utils import get_remote_cert_fingerprint, gen_random_string
from silenttrinity.core.client.stats import ClientConnectionStats
from silenttrinity.core.client.event_handlers import ClientEventHandlers
from silenttrinity.core.client.server_response import ServerResponse
from silenttrinity.core.client.contexts.listeners import Listeners
from silenttrinity.core.client.contexts.sessions import Sessions
from silenttrinity.core.client.contexts.modules import Modules
from silenttrinity.core.client.contexts.stagers import Stagers
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit.application import run_in_terminal


class ClientConnection:
    def __init__(self, url: str):
        self.alias = f"TS-{gen_random_string(5)}"
        self.url = urlparse(url)
        self.stats = ClientConnectionStats()
        self.event_handlers = ClientEventHandlers(self)
        self.msg_queue =  asyncio.Queue(maxsize=1)
        self.contexts = [
            Listeners(),
            Sessions(),
            Modules(),
            Stagers()
        ]

        self.task = None
        self.ws = None
        self.ssl_context = None
        #self.connected = asyncio.Future()

        if self.url.scheme == 'wss':
            self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            self.ssl_context.check_hostname = False
            self.ssl_context.verify_mode = ssl.CERT_NONE
        else:
            logging.warning('SECURITY WARNING: comms between client and server will be in cleartext!')

    def generate_auth_header(self, username, password):
        client_digest = hmac.new(password.encode(), msg=b'silenttrinity', digestmod=sha512).hexdigest()
        header_value = b64encode(f"{username}:{client_digest}".encode()).decode()
        return Headers({'Authorization': header_value})

    def start(self):
        def connect_callback(task):
            try:
                task.result()
            except asyncio.CancelledError:
                self.stats.CONNECTED = False
                logging.debug("Connection task cancelled")
            except websockets.exceptions.InvalidStatusCode as e:
                logging.error(e)
                logging.error('Unable to authenticate to team server, wrong password?')
            except ConnectionRefusedError as e:
                logging.error(e)
                logging.error('Error connecting to team server: connection was refused')

        self.task = asyncio.create_task(self.connect())
        self.task.add_done_callback(connect_callback)

    def stop(self):
        logging.debug(f"Cancelling connection task for {self.url.hostname}:{self.url.port}")
        self.task.cancel()

    async def connect(self):
        url = f"{self.url.scheme}://{self.url.hostname}:{self.url.port}"
        logging.debug(f'Connecting to {url}')
        while True:
            try:
                if self.url.scheme == 'wss':
                    logging.debug(f"Attempting to retrieve cert fingerprint of {self.url.hostname}:{self.url.port}")

                    server_cert_fingerprint = get_remote_cert_fingerprint(self.url.hostname, self.url.port)
                    logging.warning(
                        (f"Team Server ({self.url.hostname}:{self.url.port}) "
                        f"certificate fingerprint is {server_cert_fingerprint.hex()} "
                        "make sure this matches the output from the server!")
                    )

                async with websockets.connect(
                    url, 
                    extra_headers=self.generate_auth_header(
                        self.url.username,
                        self.url.password
                    ), 
                    ssl=self.ssl_context, 
                    ping_interval=None, # We disable the built-in ping/heartbeat mechanism and use our own
                    ping_timeout=None
                ) as ws:

                    logging.info(f'Connected to {url}')
                    self.stats.CONNECTED = True
                    self.ws = ws

                    await asyncio.wait([
                        self.data_handler(),
                        self.heartbeat()
                    ])
            except ConnectionRefusedError as e:
                logging.error(e)
                logging.error('Error connecting to team server: connection was refused')
                self.stats.CONNECTED = False

            await asyncio.sleep(5)

    async def data_handler(self):
        #self.connected.set_result(True)
        async for data in self.ws:
            data = json.loads(data)

            if data['type'] == "message":
                logging.debug(f'Got message from server: {data}')
                await self.msg_queue.put(data)

            elif data['type'] == 'event':
                logging.debug(f'Got event from server: {data}')
                try:
                    event_handler = functools.partial(
                        getattr(self.event_handlers, data['name'].lower()),
                        data=data['data']
                    )
                    with patch_stdout():
                        run_in_terminal(event_handler) #run_in_executor=True ?
                except AttributeError:
                    logging.error(f"Got event of unknown type '{data['name']}'")

        self.stats.CONNECTED = False
        logging.debug("data_handler has stopped")

    async def heartbeat(self):
        while self.ws.open: #while True?
            try:
                pong_waiter = await self.ws.ping()
                await asyncio.wait_for(pong_waiter, timeout=10)
            except (asyncio.TimeoutError, websockets.exceptions.ConnectionClosed) as e:
                logging.error(e)
                logging.error("Disconnected from teamserver")
                break
            await asyncio.sleep(10)

        self.stats.CONNECTED = False
        logging.debug("heartbeat has stopped")

    async def send(self, message):
        # We can't spawn 2 coroutines that call ws.recv() at the same time
        # so we put the actual command responses in queue and pop them on receipt
        await self.ws.send(json.dumps(message))
        while True:
            recv_msg = await self.msg_queue.get()
            self.msg_queue.task_done()
            return ServerResponse(recv_msg, self)

    def __str__(self):
        return f"{self.url.scheme}://{self.url.hostname}:{self.url.port}"
    
    def __repr__(self):
        return f"<Teamserver '{self.alias}' ({self.url.scheme}://{self.url.username}@{self.url.hostname}:{self.url.port})>"
