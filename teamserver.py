#!/usr/bin/env python3

"""
Usage: teamserver.py [-h] [-v] [--port <PORT>] [--insecure] <host> <password>

optional arguments:
    -h, --help          Show this help message and exit
    -v, --version       Show version
    -p, --port <PORT>   Port to bind to [default: 5000]
    --insecure          Start server without TLS
"""

import asyncio
import json
import logging
import os
import ssl
import pathlib
import websockets
import signal
import http
import functools
import hmac
import traceback
import core.events as events
from termcolor import colored
from docopt import docopt
from base64 import b64decode
from websockets import WebSocketServerProtocol
from hashlib import sha512
from typing import Dict, List, Any
from core.teamserver.db import AsyncSTDatabase
from core.teamserver.users import Users, UsernameAlreadyPresentError
from core.teamserver.contexts import Listeners, Sessions, Modules, Stagers
from core.utils import create_self_signed_cert, get_cert_fingerprint, decode_auth_header, CmdError, get_ips


class TeamServer:
    def __init__(self):
        self.users = Users()
        self.loop = asyncio.get_running_loop()
        self.contexts = {
            'listeners': Listeners(self),
            'sessions': Sessions(self),
            'modules': Modules(self),
            'stagers': Stagers(self),
            'users': self.users
        }

    async def process_client_message(self, user, path, data):
        message = json.loads(data)
        logging.debug(f"Received message from {user.name}@{user.ip} path:{path} msg: {message}")
        status = 'error'

        try:
            ctx = self.contexts[message['ctx'].lower()]
        except KeyError:
            traceback.print_exc()
            result = f"Context '{message['ctx'].lower()}' does not exist"
            logging.error(result)
        else:
            try:
                cmd_handler = getattr(ctx, message['cmd'])
                result = cmd_handler(**message['args'])
                status = 'success'
            except AttributeError:
                traceback.print_exc()
                result = f"Command '{message['cmd']}' does not exist in context '{message['ctx'].lower()}'"
            except CmdError as e:
                result = str(e)
            except Exception as e:
                traceback.print_exc()
                result = f"Exception when executing command '{message['cmd']}': {e}"
                logging.error(result)

        await user.send({
                'type': 'message',
                'id': message['id'],
                'ctx': message['ctx'],
                'name': message['cmd'],
                'status': status,
                'result': result
        })

    async def update_server_stats(self):
        stats = {**{str(ctx): dict(ctx) for ctx in self.contexts.values()}, 'ips': get_ips()} 
        await self.users.broadcast_event(events.STATS_UPDATE, stats)

    async def update_available_loadables(self):
        loadables = {str(ctx): [loadable.name for loadable in ctx.loaded] for ctx in self.contexts.values() if hasattr(ctx, 'loaded')}
        await self.users.broadcast_event(events.LOADABLES_UPDATE, loadables)

    async def connection_handler(self, websocket, path):
        try:
            user = await self.users.register(websocket)
            await self.update_server_stats()
            await self.update_available_loadables()
            logging.info(f"New client connected {user.name}@{user.ip}")
        except UsernameAlreadyPresentError as e:
            logging.error(f"{websocket.remote_address[0]}: {e}")
            return

        while True:
            try:
                data = await asyncio.wait_for(websocket.recv(), timeout=20)
            except asyncio.TimeoutError:
                # No data in 20 seconds, check the connection.
                logging.debug(f"No data from {user.name}@{user.ip} after 20 seconds, sending ping")
                try:
                    pong_waiter = await websocket.ping()
                    await asyncio.wait_for(pong_waiter, timeout=10)
                except asyncio.TimeoutError:
                    # No response to ping in 10 seconds, disconnect.
                    logging.debug(f"No pong from {user.name}@{user.ip} after 10 seconds, closing connection")
                    self.users.unregister(user.name)
                    await self.update_server_stats()
                    return

            except websockets.exceptions.ConnectionClosed:
                logging.debug(f"Connection closed by client")
                self.users.unregister(user.name)
                await self.update_server_stats()
                return
            else:
                await self.process_client_message(user, path, data)


class STWebSocketServerProtocol(WebSocketServerProtocol):
    async def process_request(self, path, request_headers):
        try:
            username, password_digest = decode_auth_header(request_headers)
            if not hmac.compare_digest(password_digest, teamserver_digest):
                logging.error(f"User {username} failed authentication")
                return http.HTTPStatus.UNAUTHORIZED, [], b'UNAUTHORIZED\n'
        except KeyError:
            logging.error('Received handshake with no authorization header')
            return http.HTTPStatus.FORBIDDEN, [], b'FORBIDDEN\n'

        logging.info(f"User {username} authenticated successfully")


async def server(stop):
    if not os.path.exists('./data/st.db'):
        logging.info('Creating database')
        await AsyncSTDatabase.create_db_and_schema()

    ts = TeamServer()

    ssl_context = None
    if not args['--insecure']:
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        try:
            ssl_context.load_cert_chain(
                pathlib.Path('data', 'chain.pem')
            )
        except FileNotFoundError:
            create_self_signed_cert()
            ssl_context.load_cert_chain(
                pathlib.Path('data', 'chain.pem')
            )

        server_cert_fingerprint = get_cert_fingerprint(pathlib.Path('data', 'cert.pem'))
        logging.warning(
            (f"{colored('Teamserver certificate fingerprint:', 'yellow')} "
             f"{colored(server_cert_fingerprint.hex(), 'red')}")
        )

    async with websockets.serve(
        ts.connection_handler,
        host=args['<host>'],
        port=int(args['--port']),
        create_protocol=STWebSocketServerProtocol,
        ssl=ssl_context,
        ping_interval=None,
        ping_timeout=None
    ):
    
        logging.info(colored(f"Teamserver started on {args['<host>']}:{args['--port']}", "yellow"))

        await stop

if __name__ == '__main__':
    args = docopt(__doc__, version='0.4.0dev')

    loop = asyncio.get_event_loop()
    teamserver_digest = hmac.new(args['<password>'].encode(), msg=b'silenttrinity', digestmod=sha512).hexdigest()

    stop = asyncio.Future()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set_result, None)

    if args['--insecure']:
        logging.warning('SECURITY WARNING: --insecure flag passed, communication between client and server will be in cleartext!')

    loop.run_until_complete(server(stop))
