from silenttrinity.core.utils import get_path_in_package
from silenttrinity.core.teamserver.module import Module


class STModule(Module):
    def __init__(self):
        self.name = 'boo/dcom'
        self.language = 'boo'
        self.description = 'Move laterally using DCOM'
        self.author = '@Daudau'
        self.references = []
        self.options = {
            'Host': {
                'Description'   :   'Target IP or Hostname',
                'Required'      :   True,
                'Value'         :   '127.0.0.1'
            },
            'Method': {
                'Description'   :   'DCOM execution method to use. Possible values: mmc20_application, ShellWindows, ShellBrowserWindow, \r\nCheckDomain, ServiceCheck, MinimizeAll, ServiceStop, ServiceStart, DetectOffice, RegisterXLL and ExcelDDE.',
                'Required'      :   True,
                'Value'         :   'mmc20_application'
            },
            'Command': {
                'Description'   :   'Command to Execute',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Parameters': {
                'Description'   :   'Command parameters',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Directory': {
                'Description'   :   'Working directory. If empty, will use the current one.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'ServiceName': {
                'Description'   :   'Service name while using serviceCheck, serviceStop or serviceStart DCOM methods',
                'Required'      :   False,
                'Value'         :   ''
            },
            'DllPath': {
                'Description'   :   'Dll path while using registerxll DCOM method',
                'Required'      :   False,
                'Value'         :   ''
            }
        }

    def payload(self):
        with open(get_path_in_package('core/teamserver/modules/boo/src/dcom.boo'), 'r') as module_src:
            src = module_src.read()
            src = src.replace('TARGET', self.options['Host']['Value'])
            src = src.replace('METHOD', self.options['Method']['Value'])
            src = src.replace('COMMAND', self.options['Command']['Value'])
            src = src.replace('PARAMETERS', self.options['Parameters']['Value'])
            src = src.replace('DIRECTORY', self.options['Directory']['Value'])
            src = src.replace('SERVICE_NAME', self.options['ServiceName']['Value'])
            src = src.replace('DLL_PATH', self.options['DllPath']['Value'])
            return src
