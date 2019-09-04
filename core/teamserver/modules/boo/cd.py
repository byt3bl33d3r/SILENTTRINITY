from core.teamserver.module import Module


class STModule(Module):
    def __init__(self):
        self.name = 'boo/cd'
        self.language = 'boo'
        self.description = 'Changes the current working directory'
        self.author = '@Daudau'
        self.references = []
        self.options = {
            'Path': {
                'Description'   :   'The path of the directory to got to. Can be relative or absolute.',
                'Required'      :   True,
                'Value'         :   ""
            }
        }

    def payload(self):
        with open('core/teamserver/modules/boo/src/cd.boo', 'r') as module_src:
            src = module_src.read()
            src = src.replace('PATH', self.options['Path']['Value'])
            return src
