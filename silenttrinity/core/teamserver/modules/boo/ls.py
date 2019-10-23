from silenttrinity.core.utils import get_path_in_package
from silenttrinity.core.teamserver.module import Module


class STModule(Module):
    def __init__(self):
        self.name = 'boo/ls'
        self.language = 'boo'
        self.description = 'Gets a directory listing of a directory'
        self.author = '@Daudau'
        self.references = []
        self.options = {
            'Path': {
                'Description'   :   'The path of the directory to get a listing of. Current directory by default',
                'Required'      :   False,
                'Value'         :   ""
            }
        }

    def payload(self):
        with open(get_path_in_package('core/teamserver/modules/boo/src/ls.boo'), 'r') as module_src:
            src = module_src.read()
            src = src.replace('PATH', self.options['Path']['Value'])
            return src
