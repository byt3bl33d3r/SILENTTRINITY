from core.teamserver.module import Module


class STModule(Module):
    def __init__(self):
        self.name = 'boo/impersonateuser'
        self.language = 'boo'
        self.description = 'Find a process owned by the specificied user and impersonate the token.\r\nUsed to execute subsequent commands as the specified user. (Requires Admin)'
        self.author = '@Daudau'
        self.references = []
        self.options = {
            'Username': {
                'Description'   :   'User to impersonate. "DOMAIN\\\\Username" format expected.',
                'Required'      :   False,
                'Value'         :   ""
            }
        }

    def payload(self):
        with open('core/teamserver/modules/boo/src/impersonateuser.boo', 'r') as module_src:
            src = module_src.read()
            src = src.replace('USERNAME', self.options['Username']['Value'])
            return src
