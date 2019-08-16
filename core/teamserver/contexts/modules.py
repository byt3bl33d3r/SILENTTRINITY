import types
import asyncio
import core.events as events
from copy import deepcopy
from core.teamserver import ipc_server
from core.teamserver.loader import Loader
from core.utils import CmdError
from core.teamserver.job import Job


class Modules(Loader):
    name = 'modules'
    description = 'Modules menu'

    def __init__(self, teamserver):
        self.teamserver = teamserver
        self.modules = []
        self.selected = None
        super().__init__(type="module", paths=["core/teamserver/modules/boo"])

    def list(self, name: str = None):
        return {m.name: m.description for m in self.loaded}
    
    def use(self, name: str):
        for m in self.loaded:
            if m.name.lower() == name.lower():
                self.selected = deepcopy(m)
                return dict(self.selected)

        raise CmdError(f"No module available named '{name.lower()}'")

    def options(self):
        if not self.selected:
            raise CmdError("No module selected")
        return self.selected.options

    def set(self, name: str, value: str):
        if not self.selected:
            raise CmdError("No module selected")

        try:
            self.selected[name] = value
        except KeyError:
            raise CmdError(f"Unknown option '{name}'")

    def run(self, guids):
        for guid in guids:
            ipc_server.publish_event(events.NEW_JOB, (guid, Job(module=self.selected)))
    
    def reload(self):
        self.get_loadables()
        asyncio.create_task(
            self.teamserver.update_available_loadables()
        )

    def get_selected(self):
        if self.selected:
            return dict(self.selected)

    def __iter__(self):
        yield ('loaded', len(self.loaded))

    def __str__(self):
        return self.__class__.__name__.lower()
