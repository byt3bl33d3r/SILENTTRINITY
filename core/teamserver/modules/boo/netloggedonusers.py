from core.teamserver.module import Module


class STModule(Module):
    def __init__(self):
        self.name = 'boo/netloggedonusers'
        self.language = 'boo'
        self.description = 'Get a list of logged on users from a remote computer.'
        self.author = '@Daudau'
        self.references = []
        self.options = {
            'ComputerName': {
                'Description': 'Computer name to query for logged on users. If not set, will run on local machine.',
                'Required': False,
                'Value': ""
            }
        }

    def payload(self):
        with open('core/teamserver/modules/boo/src/netloggedonusers.boo', 'r') as module_src:
            src = module_src.read()
            src = src.replace('COMPUTER_NAME', str(self.options['ComputerName']['Value']))
            return src
