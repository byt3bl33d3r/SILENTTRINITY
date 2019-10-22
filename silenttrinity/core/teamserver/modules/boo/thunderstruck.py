from silenttrinity.core.utils import get_path_in_package
from silenttrinity.core.teamserver.module import Module


class STModule(Module):
    def __init__(self):
        self.name = 'boo/thunderstruck'
        self.language = 'boo'
        self.description = 'Play Thunderstruck as LOUD AS POSSIBLE!!!!'
        self.author = 'Devin Madewell'
        self.references = []
        self.options = {
            'VideoURL': {
                'Description'   :   'Other YouTube video URL to play instead of Thunderstruck.',
                'Required'      :   False,
                'Value'         :   'https://youtu.be/v2AC41dglnM'
            },
            'Duration': {
                'Description'   :   'Duration of Volume Up sequence',
                'Required'      :   False,
                'Value'         :   '2'
            },
            'Frequency': {
                'Description'   :   'Frequency of max Volume Up routine (in milliseconds)',
                'Required'      :   False,
                'Value'         :   '2000'
            }
        }

    def payload(self):
        with open(get_path_in_package('core/teamserver/modules/boo/src/thunderstruck.boo'), 'r') as module_src:
            src = module_src.read()
            src = src.replace('SITE', self.options['VideoURL']['Value'])
            src = src.replace('MINS', self.options['Duration']['Value'])
            src = src.replace('MILS', self.options['Frequency']['Value'])
            return src
