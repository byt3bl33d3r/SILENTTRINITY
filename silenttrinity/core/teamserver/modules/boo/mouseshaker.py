from silenttrinity.core.utils import get_path_in_package
from silenttrinity.core.teamserver.module import Module


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
        with open(get_path_in_package('core/teamserver/modules/boo/src/mouseshaker.boo'), 'r') as module_src:
            src = module_src.read()
            src = src.replace('OFFSET', str(self.options['Offset']['Value']))
            return src
