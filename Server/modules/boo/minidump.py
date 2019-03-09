from core.module import Module


class STModule(Module):
    def __init__(self):
        super().__init__()
        self.name = 'boo/minidump'
        self.language = 'boo'
        self.description = 'Creates a memorydump of LSASS via Native Win32 API Calls'
        self.author = '@byt3bl33d3r'
        self.options = {
            'Dumpfile': {
                'Description': 'The Path of the dumpfile',
                'Required': False,
                'Value': "C:\\\\WINDOWS\\\\Temp\\\\debug.bin"
            },
        }

    def payload(self):
        with open('modules/boo/src/minidump.boo', 'r') as module_src:
            src = module_src.read()
            src = src.replace('DUMPFILE_PATH', self.options['Dumpfile']['Value'])
            return src
