from core.teamserver.module import Module


class STModule(Module):
    def __init__(self):
        self.name = 'boo/specialtokengroupprivs'
        self.language = 'boo'
        self.description = 'Retrieve *special* user privileges'
        self.author = '@Daudau'
        self.references = []
        self.options = {}

    def payload(self):
        with open('core/teamserver/modules/boo/src/specialtokengroupprivs.boo', 'r') as module_src:
            src = module_src.read()
            return src
