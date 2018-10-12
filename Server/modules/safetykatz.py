class STModule:
    def __init__(self):
        self.name = 'safetykatz'
        self.description = 'Creates a minidump of LSASS via Win32 API Calls, loads Mimikatz in memory and parses the dump for creds'
        self.author = '@byt3bl33d3r - @davidtavarez'
        self.options = {
            'Dumpfile': {
                'Description': 'The Path of the dumpfile',
                'Required': False,
                'Value': "C:\\\\WINDOWS\\\\Temp\\\\debug.bin"
            },
        }

    def payload(self):
        with open('modules/src/safetykatz.py', 'r') as module_src:
            src = module_src.read()
            src = src.replace('DUMPFILE_PATH', self.options['Dumpfile']['Value'])
            return bytearray(src,'utf8')
