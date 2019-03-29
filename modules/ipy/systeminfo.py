class STModule:
    def __init__(self):
        self.name = 'ipy/systeminfo'
        self.language = 'ipy'
        self.description = 'Enumerates basic system information.'
        self.author = '@daddycocoaman'
        self.options = {}

    def payload(self):
        with open('modules/ipy/src/systeminfo.py', 'r') as module_src:
            src = module_src.read()
            return src
