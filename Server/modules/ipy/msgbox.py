from core.module import Module


class STModule(Module):
    def __init__(self):
        super().__init__()
        self.name = 'ipy/msgbox'
        self.language = 'ipy'
        self.description = 'Pop a message box'
        self.author = '@byt3bl33d3r'
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
        with open('modules/ipy/src/msgbox.py', 'r') as module_src:
            src = module_src.read()
            src = src.replace('WINDOW_TITLE', self.options['Title']['Value'])
            src = src.replace('WINDOW_TEXT', self.options['Text']['Value'])
            return src
