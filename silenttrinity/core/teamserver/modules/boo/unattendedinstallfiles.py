from silenttrinity.core.utils import get_path_in_package
from silenttrinity.core.teamserver.module import Module


class STModule(Module):
    def __init__(self):
        self.name = 'boo/unattendedinstallfiles'
        self.language = 'boo'
        self.description = 'Find Unattended Install Files'
        self.author = '@Daudau'
        self.references = []
        self.options = {}

    def payload(self):
        with open(get_path_in_package('core/teamserver/modules/boo/src/unattendedinstallfiles.boo'), 'r') as module_src:
            src = module_src.read()
            return src
