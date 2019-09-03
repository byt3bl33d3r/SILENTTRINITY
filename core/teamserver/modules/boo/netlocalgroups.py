from core.teamserver.module import Module


class STModule(Module):
    def __init__(self):
        self.name = 'boo/netlocalgroups'
        self.language = 'boo'
        self.description = 'Get a list of local groups from a remote computer.'
        self.author = '@Daudau'
        self.references = []
        self.options = {
            'ComputerName': {
                'Description': 'Computer name to query for local groups. If not set, will run on local machine.',
                'Required': False,
                'Value': ""
            }
        }

    def payload(self):
        with open('core/teamserver/modules/boo/src/netlocalgroups.boo', 'r') as module_src:
            src = module_src.read()
            src = src.replace('COMPUTER_NAME', str(self.options['ComputerName']['Value']))
            return src
