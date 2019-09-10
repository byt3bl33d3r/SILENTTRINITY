from core.teamserver.module import Module


class STModule(Module):
    def __init__(self):
        self.name = 'boo/rick-astley'
        self.language = 'boo'
        self.description = 'Never Gonna Give You Up!'
        self.author = 'Devin Madewell'
        self.references = []
        self.options = {}

    def payload(self):
        with open('core/teamserver/modules/boo/src/rick-astley.boo', 'r') as module_src:
            src = module_src.read()
            return src
