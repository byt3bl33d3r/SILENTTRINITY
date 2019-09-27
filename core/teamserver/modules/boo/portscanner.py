from core.teamserver.module import Module


class STModule(Module):
    def __init__(self):
        self.name = 'boo/portscanner'
        self.language = 'boo'
        self.description = 'Scan for open ports on local or remote machine'
        self.author = '@hackabean, @munirusman'
        self.references = []
        self.options = {
            'PORTSTART': {
                'Description': 'Start of the port for scanning',
                'Required': True,
                'Value': ''
            },
            'PORTEND': {
                'Description': 'End of the port for scanning',
                'Required': True,
                'Value': ''
            },
            'CTRTHREAD': {
                'Description': 'How many threads to use, more is faster',
                'Required': False,
                'Value': ''
            },
            'HOST': {
                'Description': 'IP address of the host to scan',
                'Required': True,
                'Value': ''
            }


        }

    def payload(self):
        with open('core/teamserver/modules/boo/src/portscanner.boo', 'r') as module_src:
            src = module_src.read()
            src = src.replace('PORTSTART', str(self.options['PORTSTART']['Value']))
            src = src.replace('PORTEND', str(self.options['PORTEND']['Value']))
            src = src.replace('CTRTHREAD', str(self.options['CTRTHREAD']['Value']))
            src = src.replace('HOST', str(self.options['HOST']['Value']))
            return src