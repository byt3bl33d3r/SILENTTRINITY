from silenttrinity.core.utils import get_path_in_package
from silenttrinity.core.teamserver.module import Module


class STModule(Module):
    def __init__(self):
        self.name = 'boo/testav'
        self.language = 'boo'
        self.description = 'Test if an antivirus is installed via the resolution of the service virtual SID.'
        self.author = '@remiescourrou'
        self.references = []
        self.options = {
            'ComputerName': {
                'Description': 'Computer name to query for antivirus. If not set, will run on local machine.',
                'Required': False,
                'Value': ""
            }
        }

    def payload(self):
        with open(get_path_in_package('core/teamserver/modules/boo/src/testAV.boo'), 'r') as module_src:
            src = module_src.read()
            src = src.replace('COMPUTER_NAME', str(self.options['ComputerName']['Value']))
            return src
