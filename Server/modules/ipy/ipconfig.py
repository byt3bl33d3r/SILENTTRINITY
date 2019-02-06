class STModule:
    def __init__(self):
        self.name = 'ipy/ipconfig'
        self.language = 'ipy'
        self.description = 'Enumerates network interfaces.'
        self.author = '@daddycocoaman'
        self.options = {}

    def payload(self):
        with open('modules/ipy/src/ipconfig.py', 'r') as module_src:
            src = module_src.read()
            return src
