from silenttrinity.core.utils import get_path_in_package
from silenttrinity.core.teamserver.module import Module


class STModule(Module):
    def __init__(self):
        self.name = 'boo/msgbox'
        self.language = 'boo'
        self.description = 'Pop a message box'
        self.author = '@byt3bl33d3r'
        self.references = []
        self.options = {
            'Title': {
                'Description'   :   'Window title',
                'Required'      :   False,
                'Value'         :   'Pwned'
            },
            'Text': {
                'Description'   :   'Window text',
                'Required'      :   False,
                'Value'         :   "I'm in your computerz"
            }
        }

    def payload(self):
        with open(get_path_in_package('core/teamserver/modules/boo/src/msgbox.boo'), 'r') as module_src:
            src = module_src.read()
            src = src.replace('WINDOW_TITLE', self.options['Title']['Value'])
            src = src.replace('WINDOW_TEXT', self.options['Text']['Value'])
            return src
