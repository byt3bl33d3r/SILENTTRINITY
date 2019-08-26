from core.teamserver.module import Module


class STModule(Module):
    def __init__(self):
        self.name = 'boo/persistence'
        self.language = 'boo'
        self.description = 'Basic module allowing you to get persistence through registry key'
        self.author = ''
        self.references = []
        self.options = {
                'Base_Key' : {
                        'Description'   :   'Specifies the base of your register key : 0 - ClassesRoot, 1 - CurrentConfig, 2 - CurrentUser, 3 - DynData, 4 - LocalMachine, 5 - PerformancesData, 6 - Users',
                        'Required'      :   True,
                        'Value'         :   2
                    },
                'Key' : {
                        'Description'   :   'Path of the register key',
                        'Required'      :   True,
                        'Value'         :   'SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run'
                    },
                'Name' : {
                        'Description'   :   'Set the parameter "Name" of your entry',
                        'Required'      :   True,
                        'Value'         :   ''
                    },
                'Data' : {
                        'Description'   :   'Set the parameter "Data" of your entry (Probably the path of the binary you want to execute)',
                        'Required'      :   True,
                        'Value'         :   ''
                    }
                }

    def payload(self):
        with open('core/teamserver/modules/boo/src/persistence.boo', 'r') as module_src:
            src = module_src.read()
            base_key_opt = self.options['Base_Key']['Value']
            base_key = ''

            if base_key_opt == 0:
                base_key = 'ClassesRoot'
            elif base_key_opt == 1:
                base_key = 'CurrentConfig'
            elif base_key_opt == 2:
                base_key = 'CurrentUser'
            elif base_key_opt == 3:
                base_key = 'DynData'
            elif base_key_opt == 4:
                base_key = 'LocalMachine'
            elif base_key_opt == 5:
                base_key = 'PerformancesData'
            elif base_key_opt == 6:
                base_key = 'Users'
            
            src = src.replace('BASE_KEY', base_key)
            src = src.replace('KEY', self.options['Key']['Value'])
            src = src.replace('NAME', self.options['Name']['Value'])
            src = src.replace('DATA', self.options['Data']['Value'])

            return src
