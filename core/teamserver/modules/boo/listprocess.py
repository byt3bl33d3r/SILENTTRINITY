from core.teamserver.module import Module


class STModule(Module):
    def __init__(self):
        self.name = 'boo/listprocess'
        self.language = 'boo'
        self.description = 'List running processes on the system'
        self.author = '@Daudau'
        self.references = ["System.Management"]
        self.options = {}

    def payload(self):
        with open('core/teamserver/modules/boo/src/listprocess.boo', 'r') as module_src:
            src = module_src.read()
            return src
