import asyncio
import json
import logging
from silenttrinity.core.events import Events
from silenttrinity.core.utils import decode_auth_header

class UsernameAlreadyPresentError(Exception):
    pass

class User:
    def __init__(self, name, websocket):
        self.name = name
        self.websocket = websocket
        self.ip, self.port = websocket.remote_address

    async def send(self, data):
        await self.websocket.send(json.dumps(data))
    
    async def disconnect(self):
        await self.websocket.close()
    
    def __eq__(self, other):
        if not isinstance(other, User):
            return NotImplemented

        return self.websocket == other.websocket and self.name == other.name and self.ip == other.ip and self.port == other.port

    def __hash__(self):
        return hash((self.websocket, self.ip, self.port, self.name))

    def __str__(self):
        return f"User(username='{self.name}' address={self.ip}:{self.port} websocket='{self.websocket}')"

    def __repr__(self):
        return f"User(username='{self.name}' address={self.ip}:{self.port}')"

    def __iter__(self):
        yield ('name', self.name)
        yield ('ip', self.ip)
        yield ('port', self.port)

class Users:
    def __init__(self):
        self.users = set()

    async def broadcast_event(self, event, data, exclude=[]):
        message = {
            'type': 'event', 
            'name': event.name,
            'data': data
        }
        try:
            await asyncio.wait([user.send(message) for user in self.users if user not in exclude])
        except ValueError:
            logging.warning(f"Attempted to send broadcast event to {len(self.users)} user(s) but they were also part of the exclude list: {exclude}")

    def unregister(self, name: str):
        users = set(self.users)
        for user in users:
            if user.name == name:
                self.users.remove(user)

    async def register(self, websocket):
        name, _ = decode_auth_header(websocket.request_headers)
        if list(filter(lambda x: x.name == name, self.users)):
            raise UsernameAlreadyPresentError(f"User with username '{name}' already exists")

        user = User(name, websocket)
        self.users.add(user)
        await self.broadcast_event(Events.USER_LOGIN, f"{user.name} has joined!", exclude=[user])
        return user

    def __len__(self):
        return len(self.users)
    
    def __iter__(self):
        for user in self.users:
            yield (user.name, dict(user))

    def __str__(self):
        return self.__class__.__name__.lower()
