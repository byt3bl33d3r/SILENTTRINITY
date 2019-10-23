from silenttrinity.core.utils import get_path_in_package
from silenttrinity.core.teamserver.module import Module


class STModule(Module):
    def __init__(self):
        self.name = 'boo/maketoken'
        self.language = 'boo'
        self.description = 'Ends the impersonation of any token, reverting back to the initial token associated with the current process.\r\n Useful in conjuction with modules that impersonate a token and do not automatically RevertToSelf, \r\nsuch as: impersonateuser, impersonateprocess, getsystem, and maketoken.'
        self.author = '@Daudau'
        self.references = []
        self.options = {
            'Username': {
                'Description'   :   'Username to authenticate as.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Domain': {
                'Description'   :   'Domain to authenticate the user to.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Password': {
                'Description'   :   'Password to authenticate the user.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'LogonType': {
                'Description'   :   'LogonType to use. Defaults to LOGON32_LOGON_NEW_CREDENTIALS. Pssible values:\r\n',
                'Required'      :   True,
                'Value'         :   'LOGON32_LOGON_NEW_CREDENTIALS'
            }
        }

    def payload(self):
        with open(get_path_in_package('core/teamserver/modules/boo/src/maketoken.boo'), 'r') as module_src:
            src = module_src.read()
            src = src.replace('USERNAME', str(self.options['Username']['Value']).upper())
            src = src.replace('DOMAIN', str(self.options['Domain']['Value']).upper())
            src = src.replace('PASSWORD', str(self.options['Password']['Value']).upper())
            src = src.replace('LOGON_TYPE', str(self.options['LogonType']['Value']).upper())
            return src
