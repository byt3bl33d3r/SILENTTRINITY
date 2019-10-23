from silenttrinity.core.utils import get_path_in_package
from silenttrinity.core.teamserver.module import Module


class STModule(Module):
    def __init__(self):
        self.name = 'boo/portscanner'
        self.language = 'boo'
        self.description = 'Scan for open ports on local or remote machine'
        self.author = '@hackabean, @PhilipMur'
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
                'Description': 'How many threads to use, more is faster, default 700',
                'Required': True,
                'Value': '700'
            },
            'HOST': {
                'Description': 'IP address of the host to scan',
                'Required': True,
                'Value': ''
                            },
            'TIMEOUT': {
                'Description': 'How long to wait before giving up. Default 50, higher number gives more accurate readings',
                'Required': True,
                'Value': '50'
            }
        }

    def payload(self):
        with open(get_path_in_package('core/teamserver/modules/boo/src/portscanner.boo'), 'r') as module_src:
            src = module_src.read()
            src = src.replace('PORTSTART', str(self.options['PORTSTART']['Value']))
            src = src.replace('PORTEND', str(self.options['PORTEND']['Value']))
            src = src.replace('CTRTHREAD', str(self.options['CTRTHREAD']['Value']))
            src = src.replace('HOST', str(self.options['HOST']['Value']))
            src = src.replace('TIMEOUT', str(self.options['TIMEOUT']['Value']))
            return src
