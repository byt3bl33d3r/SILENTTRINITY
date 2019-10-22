import asyncio
from copy import deepcopy
from silenttrinity.core.events import Events
from silenttrinity.core.utils import CmdError, get_path_in_package
from silenttrinity.core.teamserver import ipc_server
from silenttrinity.core.teamserver.loader import Loader


class Stagers(Loader):
    name = 'stagers'
    description = 'Stagers menu'

    def __init__(self, teamserver):
        self.teamserver = teamserver
        self.selected = None

        ipc_server.attach(Events.GET_STAGERS, self._get_stagers)
        super().__init__(type="stager", paths=[get_path_in_package("core/teamserver/stagers/")])

    def _get_stagers(self, name):
        if name:
            try:
                return list(filter(lambda stager: stager.name == name, self.loaded))[0]
            except IndexError:
                return
        else:
            return self.loaded

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
                guid, psk, generated_stager = self.selected.generate(l)
                self.teamserver.contexts['sessions']._register(guid, psk)

                return {
                    "output": generated_stager,
                    "suggestions": self.selected.suggestions,
                    "extension": self.selected.extension
                }

        raise CmdError(f"No listener running with name '{listener_name}'")

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

    def __str__(self):
        return self.__class__.__name__.lower()

    def __iter__(self):
        yield ('loaded', len(self.loaded))
