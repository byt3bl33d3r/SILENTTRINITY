from core.teamserver.module import Module


class STModule(Module):
    def __init__(self):
        self.name = 'boo/uaccomputerdefaults'
        self.language = 'boo'
        self.description = 'Bypasses UAC using Device Manager through Management Console.'
        self.author = '@hackabean, @JulioUrena, rootm0s'
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
            }

        }

    def payload(self):
        with open('core/teamserver/modules/boo/src/bypassUACComputerDefaults.boo', 'r') as module_src:
            src = module_src.read()
            src = src.replace('BINARY', str(self.options['Binary']['Value']))
            src = src.replace('ARGUMENTS', str(self.options['Arguments']['Value']))
            src = src.replace('PATH', str(self.options['Path']['Value']))
            return src