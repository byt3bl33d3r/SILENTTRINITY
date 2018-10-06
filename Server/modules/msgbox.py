class STModule:
    def __init__(self):
        self.name = 'msgbox'
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

    def options(self):
        pass

    def payload(self):
        with open('modules/src/msgbox.py', 'r') as module_src:
            src = module_src.read()
            src = src.replace('WINDOW_TITLE', self.options['Title']['Value'])
            src = src.replace('WINDOW_TEXT', self.options['Text']['Value'])
            return src.encode()
