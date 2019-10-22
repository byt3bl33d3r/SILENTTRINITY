from silenttrinity.core.utils import get_path_in_package
from silenttrinity.core.teamserver.module import Module


class STModule(Module):
    def __init__(self):
        self.name = 'boo/netlocalgroupmembers'
        self.language = 'boo'
        self.description = 'Get a list of local groups from a remote computer.'
        self.author = '@Daudau'
        self.references = []
        self.options = {
            'ComputerName': {
                'Description': 'Computer name to query for local group members. If not set, will run on local machine.',
                'Required': False,
                'Value': ""
            },
            'GroupName': {
                'Description': 'Local group to search for members.',
                'Required': True,
                'Value': "Administrators"
            }
        }

    def payload(self):
        with open(get_path_in_package('core/teamserver/modules/boo/src/netlocalgroupmembers.boo'), 'r') as module_src:
            src = module_src.read()
            src = src.replace('COMPUTER_NAME', str(self.options['ComputerName']['Value']))
            src = src.replace('GROUP_NAME', str(self.options['GroupName']['Value']))
            return src
