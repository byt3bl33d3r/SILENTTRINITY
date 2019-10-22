from silenttrinity.core.utils import get_path_in_package
from silenttrinity.core.teamserver.module import Module


class STModule(Module):
    def __init__(self):
        self.name = 'boo/rdp'
        self.language = 'boo'
        self.description = 'Enable or disable Remote Desktop Protocol on a localhost via registry key'
        self.author = '@hackabean'
        self.references = []
        self.options = {
            'RDP_Status': {
                'Description': 'Enter value "enable" or "disable" to set RDP status (Requires Admin)',
                'Required': True,
                'Value': ''

            }

        }

    def payload(self):
        with open(get_path_in_package('core/teamserver/modules/boo/src/rdp.boo')) as module_src:
            src = module_src.read()
            src = src.replace('status', self.options['RDP_Status']['Value'])
            return src


