from core.teamserver.module import Module


class STModule(Module):
    def __init__(self):
        self.name = 'creds/session-goopher'
        self.language = 'boo'
        self.description = 'Searches all connected drives for PuTTY private keys and RDP connection files and parses them for relevant details. Based on SessionGopher by @arvanaghi.'
        self.author = '@matterpreter'
        self.references = []
        self.options = {
            'Path': {
                'Description'   :   'The path of the directory to got to. Can be relative or absolute.',
                'Required'      :   False,
                'Value'         :   ""
            }
        }

    def payload(self):
        with open('core/teamserver/modules/boo/src/session-goopher.boo', 'r') as module_src:
            src = module_src.read()
            return src
