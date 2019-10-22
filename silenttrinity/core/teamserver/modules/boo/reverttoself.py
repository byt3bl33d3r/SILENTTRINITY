from silenttrinity.core.utils import get_path_in_package
from silenttrinity.core.teamserver.module import Module


class STModule(Module):
    def __init__(self):
        self.name = 'boo/reverttoself'
        self.language = 'boo'
        self.description = 'Ends the impersonation of any token, reverting back to the initial token associated with the current process.\r\n Useful in conjuction with modules that impersonate a token and do not automatically RevertToSelf, \r\nsuch as: impersonateuser, impersonateprocess, getsystem, and maketoken.'
        self.author = '@Daudau'
        self.references = []
        self.options = {}

    def payload(self):
        with open(get_path_in_package('core/teamserver/modules/boo/src/reverttoself.boo'), 'r') as module_src:
            src = module_src.read()
            return src
