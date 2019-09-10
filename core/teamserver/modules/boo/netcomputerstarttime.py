from core.teamserver.module import Module


class STModule(Module):
    def __init__(self):
        self.name = 'boo/netcomputerstarttime'
        self.language = 'boo'
        self.description = 'Query a given host for start time information.'
        self.author = '@remiescourrou'
        self.references = []
        self.options = {
            'ComputerName': {
                'Description': 'Computer name to query for start time. If not set, will run on local machine.',
                'Required': False,
                'Value': ""
            }
        }

    def payload(self):
        with open('core/teamserver/modules/boo/src/netcomputerstarttime.boo', 'r') as module_src:
            src = module_src.read()
            src = src.replace('COMPUTER_NAME', str(self.options['ComputerName']['Value']))
            return src
