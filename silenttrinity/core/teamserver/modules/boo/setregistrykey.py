from silenttrinity.core.utils import get_path_in_package
from silenttrinity.core.teamserver.module import Module


class STModule(Module):
    def __init__(self):
        self.name = 'boo/setregistrykey'
        self.language = 'boo'
        self.description = 'Sets a value in the registry.'
        self.author = '@Daudau'
        self.references = []
        self.options = {
            'RegistryHive': {
                'Description'   :   'The RegistryHive to set within. (HKCU, HKLM, HKCR, HKCC or HKU)\r\nDefault: HKCU',
                'Required'      :   False,
                'Value'         :   'HKCU'
            },
            'RegistryKey': {
                'Description'   :   'The RegistryKey to set, including the hive.',
                'Required'      :   True,
                'Value'         :   ""
            },
            'RegistryValue': {
                'Description'   :   'The name of name/value pair to write to in the RegistryKey.',
                'Required'      :   True,
                'Value'         :   ""
            },
            'Value': {
                'Description'   :   'The value to write to the registry key.',
                'Required'      :   True,
                'Value'         :   ""
            },
            'ValueKind': {
                'Description'   :   'The kind of value to write to the registry key. (Binary, DWord, ExpandString, MultiString, None, QWord, String)\r\nDefault: String',
                'Required'      :   True,
                'Value'         :   "String"
            }
        }

    def payload(self):
        with open(get_path_in_package('core/teamserver/modules/boo/src/setregistrykey.boo'), 'r') as module_src:
            src = module_src.read()
            src = src.replace('REGISTRY_HIVE', str(self.options['RegistryHive']['Value']).upper())
            src = src.replace('REGISTRY_KEY', self.options['RegistryKey']['Value'])
            src = src.replace('REGISTRY_VALUE', self.options['RegistryValue']['Value'])
            src = src.replace('NEW_VALUE', self.options['Value']['Value'])
            src = src.replace('NEW_VAL_KIND', self.options['ValueKind']['Value'])
            return src
