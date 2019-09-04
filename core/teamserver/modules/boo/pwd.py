from core.teamserver.module import Module


class STModule(Module):
    def __init__(self):
        self.name = 'boo/pwd'
        self.language = 'boo'
        self.description = 'Get current directory'
        self.author = '@Daudau'
        self.references = []
        self.options = {}

    def payload(self):
        with open('core/teamserver/modules/boo/src/pwd.boo', 'r') as module_src:
            src = module_src.read()
            return src
