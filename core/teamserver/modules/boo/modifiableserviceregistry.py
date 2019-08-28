from core.teamserver.module import Module


class STModule(Module):
    def __init__(self):
        self.name = 'boo/modifiableserviceregistry'
        self.language = 'boo'
        self.description = 'Find modifiable service registry keys that may be used for privesc'
        self.author = '@Daudau'
        self.references = ["System.Management"]
        self.options = {}

    def payload(self):
        with open('core/teamserver/modules/boo/src/modifiableserviceregistry.boo', 'r') as module_src:
            src = module_src.read()
            return src
