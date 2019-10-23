from silenttrinity.core.utils import get_path_in_package
from silenttrinity.core.teamserver.module import Module


class STModule(Module):
    def __init__(self):
        self.name = 'boo/wmipersistence'
        self.language = 'boo'
        self.description = 'Creates a WMI Event, Consumer and Binding to execuate a payload.'
        self.author = '@Daudau'
        self.references = ["System.Management"]
        self.options = {
            'EventName': {
                'Description'   :   'An arbitrary name to be assigned to the new WMI Event.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'EventConsumer': {
                'Description'   :   'Specifies the action to carry out.\r\nThe options are 1 (CommandLine, i.e. OS Command) and 2 (ActiveScript, i.e. JScript or VBScript).',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Payload': {
                'Description'   :   'Specifies the CommandLine or ActiveScript payload to run.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'ProcessName': {
                'Description'   :   'Specifies the process name when the ProcessStart trigger is selected. Defaults to notepad.exe.',
                'Required'      :   True,
                'Value'         :   'notepad.exe'
            },
            'ScriptingEngine': {
                'Description'   :   'Specifies the scripting engine when the ActiveScript consumer is selected. Defaults to VBScript.\r\nThe options are 1 (JScript) and 2 (VBScript).',
                'Required'      :   True,
                'Value'         :   '2'            }
        }

    def payload(self):
        with open(get_path_in_package('core/teamserver/modules/boo/src/wmipersistence.boo'), 'r') as module_src:
            src = module_src.read()
            src = src.replace('EVENT_NAME', self.options['EventName']['Value'])
            src = src.replace('EVENT_CONSUMER', self.options['EventConsumer']['Value'])
            src = src.replace('PAYLOAD', self.options['Payload']['Value'])
            src = src.replace('PROCESS_NAME', self.options['ProcessName']['Value'])
            src = src.replace('SCRIPTING_ENGINE', self.options['ScriptingEngine']['Value'])
            return src
