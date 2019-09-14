from core.teamserver.module import Module


class STModule(Module):
    def __init__(self):
        self.name = 'boo/recentfiles'
        self.language = 'boo'
        self.description = 'Parsed "recent files" shortcuts'
        self.author = '@byt3bl33d3r'
        self.references = []
        self.options = {
            'Days': {
                'Description'   :   'Number of days ',
                'Required'      :   True,
                'Value'         :   "7"
            }
        }

    def payload(self):
        with open('core/teamserver/modules/boo/src/recentFiles.boo') as module_src:
            src = module_src.read()
            src = src.replace('LAST_DAYS', self.options['Days']['Value'])
            return src
