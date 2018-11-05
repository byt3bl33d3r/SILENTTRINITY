class STModule:
    def __init__(self):
        self.name = 'ps'
        self.description = 'Show currently running processes'
        self.author = 'Mark Bregman <@InfoSec_KB>'
        self.options = {}

    def payload(self):
        with open('modules/src/ps.py', 'r') as module_src:
            src = module_src.read()
            return src.encode()
