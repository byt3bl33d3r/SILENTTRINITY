from core.teamserver.module import Module


class STModule(Module):
    def __init__(self):
        self.name = 'boo/modifiableservices'
        self.language = 'boo'
        self.description = 'Find modifiable services that may be used for privesc'
        self.author = '@Daudau'
        self.references = ["System.Management"]
        self.options = {}

    def payload(self):
        with open('core/teamserver/modules/boo/src/modifiableservices.boo', 'r') as module_src:
            src = module_src.read()
            return src
