import os
from base64 import b64encode
from shlex import split

class STModule:
    def __init__(self):
        self.name = 'execute-assembly'
        self.description = 'Execute a .NET assembly in memory'
        self.author = '@byt3bl33d3r'
        self.options = {
            'Assembly': {
                'Description'   :   'Path to assembly',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Arguments': {
                'Description'   :   'Arguments to pass to the assembly on runtime',
                'Required'      :   False,
                'Value'         :   ""
            }
        }

    def payload(self):
        with open('modules/src/execute-assembly.py') as module:
            module = module.read()
            assembly_path = os.path.expanduser(self.options['Assembly']['Value'])
            if not os.path.exists(assembly_path):
                raise Exception("Assembly not found in specified path")

            with open(assembly_path, 'rb') as assembly:
                module = module.replace('ASSEMBLY_BASE64', b64encode(assembly.read()).decode())
                module = module.replace('ARGS', ' '.join(split(self.options['Arguments']['Value'])))
                return module.encode()
