from silenttrinity.core.teamserver.module import Module
from silenttrinity.core.utils import get_path_in_package


class STModule(Module):
    def __init__(self):
        self.name = 'boo/getdrives'
        self.language = 'boo'
        self.description = 'Gets a list of drives on the system'
        self.author = '@glid3s'
        self.references = []
        self.options = {}

    def payload(self):
        with open(get_path_in_package('core/teamserver/modules/boo/src/getdrives.boo'), 'r') as module_src:
            src = module_src.read()
            return src
