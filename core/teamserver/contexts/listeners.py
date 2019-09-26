import asyncio
import logging
import core.events as events
from time import sleep
from copy import deepcopy
from core.teamserver import ipc_server
from core.teamserver.loader import Loader
from core.utils import CmdError, gen_random_string


class Listeners(Loader):
    name = 'listeners'
    description = 'Listener menu'

    def __init__(self, teamserver):
        self.teamserver = teamserver
        self.listeners = []
        self.selected = None

        ipc_server.attach(events.GET_LISTENERS, self._get_listeners)
        super().__init__(type="listener", paths=["core/teamserver/listeners/"])

    def _get_listeners(self, name):
        if name:
            try:
                return list(filter(lambda l: l.name == name, self.listeners))[0]
            except IndexError:
                return
        else:
            return self.listeners

    def list(self, name: str, running: bool, available: bool):
        if available:
            return {l.name: dict(l) for l in self.loaded}
        return {l['Name']: dict(l) for l in self.listeners}

    def use(self, name: str):
        for l in self.loaded:
            if l.name.lower() == name.lower():
                self.selected = deepcopy(l)
                #self.selected.name = f"{l.name}-{gen_random_string(6)}"
                return dict(self.selected)

        raise CmdError(f"No listener available named '{name.lower()}'")

    def options(self):
        if not self.selected:
            raise CmdError("No listener selected")
        return self.selected.options

    def start(self):
        if not self.selected:
            raise CmdError("No listener selected")

        if len(list(filter(lambda l: l['Name'] == self.selected['Name'], self.listeners))):
            raise CmdError(f"A listener named \'{self.selected['Name']}\' already running! (Change the name and try again)")

        try:
            self.selected.start()
            logging.info(f"Started {self.selected.name} listener ({self.selected['BindIP']}:{self.selected['Port']})")
        except Exception as e:
            raise CmdError(f"Failed to start {self.selected.name} listener: {e}")
        else:
            self.listeners.append(self.selected)
            listener_json = dict(self.selected)
            self.use(self.selected.name)

            asyncio.create_task(
                self.teamserver.update_server_stats()
            )
            return dict(listener_json)

    def stop(self, name: str):
        for l in self.listeners:
            if l['Name'] == name:
                l.stop()
                while l.running:
                    sleep(0.5)
                logging.info(f"Stopped {self.selected.name} listener")
                del self.listeners[self.listeners.index(l)]
                return dict(l)

    def set(self, name: str, value: str):
        if not self.selected:
            raise CmdError("No listener selected")

        try:
            self.selected[name] = value
        except KeyError:
            raise CmdError(f"Unknown option '{name}'")
    
    def get_selected(self):
        if self.selected:
            return dict(self.selected)

    def reload(self):
        self.get_loadables()
        if self.selected:
            self.use(self.selected.name)

        asyncio.create_task(
            self.teamserver.update_available_loadables()
        )

    def __iter__(self):
        for listener in self.listeners:
            yield (listener.name, dict(listener))

    def __str__(self):
        return self.__class__.__name__.lower()
