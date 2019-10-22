from silenttrinity.core.utils import get_path_in_package
from silenttrinity.core.teamserver.module import Module


class STModule(Module):
    def __init__(self):
        self.name = 'boo/getregistrykey'
        self.language = 'boo'
        self.description = 'Gets the entries of a RegistryKey or value of a RegistryKey.'
        self.author = '@Daudau'
        self.references = []
        self.options = {
            'RegistryHive': {
                'Description'   :   'The RegistryHive to read from. (HKCU, HKLM, HKCR, HKCC or HKU)\r\nDefault: HKCU',
                'Required'      :   False,
                'Value'         :   'HKCU'
            },
            'RegistryKey': {
                'Description'   :   'The RegistryKey, including the hive, to read from.',
                'Required'      :   True,
                'Value'         :   ""
            },
            'RegistryValue': {
                'Description'   :   'The name of name/value pair to read from in the RegistryKey.\r\nIf not set, will display all subkeys.',
                'Required'      :   False,
                'Value'         :   ""
            }
        }

    def payload(self):
        with open(get_path_in_package('core/teamserver/modules/boo/src/getregistrykey.boo'), 'r') as module_src:
            src = module_src.read()
            src = src.replace('REGISTRY_HIVE', str(self.options['RegistryHive']['Value']).upper())
            src = src.replace('REGISTRY_KEY', self.options['RegistryKey']['Value'])
            src = src.replace('REGISTRY_VALUE', self.options['RegistryValue']['Value'])
            return src
