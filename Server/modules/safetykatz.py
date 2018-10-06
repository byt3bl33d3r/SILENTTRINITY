class STModule:
    def __init__(self):
        self.name = 'safetykatz'
        self.description = 'Creates a minidump of LSASS via Win32 API Calls, loads Mimikatz in memory and parses the dump for creds'
        self.author = '@byt3bl33d3r'
        self.options = {}

    def payload(self):
        with open('modules/src/safetykatz.py', 'rb') as module_src:
            return module_src.read()
