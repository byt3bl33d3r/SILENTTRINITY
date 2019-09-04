from core.teamserver.module import Module


class STModule(Module):
    def __init__(self):
        self.name = 'boo/impersonateprocess'
        self.language = 'boo'
        self.description = 'Impersonate the token of the specified process. Used to execute subsequent commands as the user \r\nassociated with the token of the specified process. (Requires Admin)'
        self.author = '@Daudau'
        self.references = []
        self.options = {
            'ProcessID': {
                'Description'   :   'ID of the process to impersonate.',
                'Required'      :   False,
                'Value'         :   ""
            }
        }

    def payload(self):
        with open('core/teamserver/modules/boo/src/impersonateprocess.boo', 'r') as module_src:
            src = module_src.read()
            src = src.replace('PROCESS_ID', self.options['ProcessID']['Value'])
            return src
