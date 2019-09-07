import asyncio
from copy import deepcopy
from core.teamserver.loader import Loader
from core.utils import CmdError, gen_random_string


class Listeners(Loader):
    name = 'listeners'
    description = 'Listener menu'

    def __init__(self, teamserver):
        self.teamserver = teamserver
        self.listeners = []
        self.selected = None
        super().__init__(type="listener", paths=["core/teamserver/listeners/"])

    def list(self, name: str, running: bool, available: bool):
        if available:
            return {l.name: dict(l) for l in self.loaded}
        return {l.name: dict(l) for l in self.listeners}

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

        if len(list(filter(lambda l: l.name == self.selected.name, self.listeners))):
            raise CmdError(f"Listener named '{self.selected.name}' already running!")

        self.selected.start()
        self.listeners.append(self.selected)

        asyncio.create_task(
            self.teamserver.update_server_stats()
        )
        return dict(self.selected)

    def stop(self, name: str):
        for l in self.listeners:
            if l['Name'] == name:
                l.stop()
                del self.listeners[self.listeners.index(l)]

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
        asyncio.create_task(
            self.teamserver.update_available_loadables()
        )

    def __iter__(self):
        for listener in self.listeners:
            yield (listener.name, dict(listener))

    def __str__(self):
        return self.__class__.__name__.lower()
