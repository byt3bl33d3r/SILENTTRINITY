from core.teamserver.module import Module


class STModule(Module):
    def __init__(self):
        self.name = 'boo/whoami'
        self.language = 'boo'
        self.description = 'Gets the username of the currently used/impersonated token.'
        self.author = '@Daudau'
        self.references = []
        self.options = {}

    def payload(self):
        with open('core/teamserver/modules/boo/src/whoami.boo', 'r') as module_src:
            src = module_src.read()
            return src
