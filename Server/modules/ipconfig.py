class STModule:
    def __init__(self):
        self.name = 'ipconfig'
        self.description = 'Enumerates network interfaces.'
        self.author = 'daddycocoaman'
        self.options = {}

    def payload(self):
        with open('modules/src/ipconfig.py', 'r') as module_src:
            src = module_src.read()
            return src.encode()
