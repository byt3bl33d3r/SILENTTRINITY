import asyncio
import core.events as events
from copy import deepcopy
from core.teamserver import ipc_server
from core.teamserver.loader import Loader
from core.utils import CmdError

class Stagers(Loader):
    name = 'stagers'
    description = 'Stagers menu'

    def __init__(self, teamserver):
        self.teamserver = teamserver
        self.stagers = []
        self.selected = None

        ipc_server.attach(events.GET_STAGERS, self.get_stagers)
        super().__init__(type="stager", paths=["core/teamserver/stagers/"])

    def list(self):
        return {s.name: dict(s) for s in self.loaded}

    def use(self, name: str):
        for s in self.loaded:
            if s.name.lower() == name.lower():
                self.selected = deepcopy(s)
                return dict(self.selected)

        raise CmdError(f"No stager available named '{name.lower()}'")

    def options(self):
        if not self.selected:
            raise CmdError("No stager selected")

        return self.selected.options

    def set(self, name: str, value: str):
        if not self.selected:
            raise CmdError("No stager selected")

        try:
            self.selected[name] = value
        except KeyError:
            raise CmdError(f"Unknown option '{name}'")
    
    def generate(self, listener_name):
        if not self.selected:
            raise CmdError("No stager selected")

        for l in self.teamserver.contexts['listeners'].listeners:
            if l['Name'] == listener_name:
                return {
                    "output": self.selected.generate(l),
                    "suggestions": self.selected.suggestions,
                    "extension": self.selected.extension
                }

        raise CmdError(f"No listener running with name '{listener_name}'")

    def get_selected(self):
        if self.selected:
            return dict(self.selected)

    def get_stagers(self, name):
        if name:
            try:
                return list(filter(lambda stager: stager.name == name, self.loaded))[0]
            except IndexError:
                return
        else:
            return self.loaded

    def reload(self):
        self.get_loadables()
        asyncio.create_task(
            self.teamserver.update_available_loadables()
        )

    def __str__(self):
        return self.__class__.__name__.lower()

    def __iter__(self):
        yield ('loaded', len(self.loaded))
