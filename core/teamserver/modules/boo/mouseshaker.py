from core.teamserver.module import Module


class STModule(Module):
    def __init__(self):
        self.name = 'boo/mouseshaker'
        self.language = 'boo'
        self.description = 'Shakes da mouse'
        self.author = '@byt3bl33d3r'
        self.references = []
        self.options = {
            'Offset': {
                'Description': 'Shake offset (higher number makes shaking more extreme)',
                'Required': False,
                'Value': 20
            }
        }

    def payload(self):
        with open('core/teamserver/modules/boo/src/mouseshaker.boo', 'r') as module_src:
            src = module_src.read()
            src = src.replace('OFFSET', str(self.options['Offset']['Value']))
            return src
