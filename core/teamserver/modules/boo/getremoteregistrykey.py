from core.teamserver.module import Module


class STModule(Module):
    def __init__(self):
        self.name = 'boo/getremoteregistrykey'
        self.language = 'boo'
        self.description = 'Gets the entries of a RegistryKey or value of a RegistryKey on a remote machine.'
        self.author = '@Daudau'
        self.references = []
        self.options = {
            'Hostname': {
                'Description'   :   'Remote hostname to connect to for remote registry.',
                'Required'      :   True,
                'Value'         :   ''
            },
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
        with open('core/teamserver/modules/boo/src/getremoteregistrykey.boo', 'r') as module_src:
            src = module_src.read()
            src = src.replace('HOSTNAME', self.options['Hostname']['Value'])
            src = src.replace('REGISTRY_HIVE', str(self.options['RegistryHive']['Value']).upper())
            src = src.replace('REGISTRY_KEY', self.options['RegistryKey']['Value'])
            src = src.replace('REGISTRY_VALUE', self.options['RegistryValue']['Value'])
            return src
