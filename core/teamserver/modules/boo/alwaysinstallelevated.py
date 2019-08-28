from core.teamserver.module import Module


class STModule(Module):
    def __init__(self):
        self.name = 'boo/alwaysinstallelevated'
        self.language = 'boo'
        self.description = 'Check if the AlwaysInstallElevated Registry Key is set'
        self.author = '@Daudau'
        self.references = []
        self.options = {}

    def payload(self):
        with open('core/teamserver/modules/boo/src/alwaysinstallelevated.boo', 'r') as module_src:
            src = module_src.read()
            return src
