from core.teamserver.module import Module
from core.utils import print_bad

class STModule(Module):
    def __init__(self):
        self.name = 'boo/uploader'
        self.language = 'boo'
        self.description = 'Uploads file'
        self.author = 'Tinydile'
        self.references = []
        self.options = {
            'Src': {
                'Description'   :   'Source File to be uploaded to',
                'Required'      :   True,
                'Value'         :   '/etc/resolv.conf'
            },
            'Dest': {
                'Description'   :   'Destination pathname\nPath delimiter is four backslashes: C:\\\\\\\\tmp\\\\\\\\result.txt\nEnd with \\\\\\\\ means directory',
                'Required'      :   True,
                'Value'         :   'C:\\\\tmp\\\\test.txt'
            }
        }

    def payload(self):
        if self.options['Src']['Value'] is None:
            print_bad("Selected file does not exists.")
            return None

        import os
        import base64
        import re

        if not os.path.exists(self.options['Src']['Value']):
            from core.utils import print_bad
            print_bad("Selected file do not exists.")
            return None

        basename = os.path.basename(self.options['Src']['Value'])
        print("Basename: " + basename)

        if re.search(r'\\\\$', self.options['Dest']['Value']):
            destination = self.options['Dest']['Value'] + basename
        else:
            destination = self.options['Dest']['Value']
        print("Destination: " + destination)


        with open(self.options['Src']['Value'], "rb") as file:
            encoded_string = base64.b64encode(file.read()).decode("utf-8")

        with open('core/teamserver/modules/boo/src/uploader.boo') as module_src:
            src = module_src.read()
            src = src.replace("DESTINATION", destination)
            src = src.replace("ENCODEDTEXT", encoded_string)
            return src
            # src = src.replace("MIMIKATZ_COMMAND", self.options['Command']['Value'])
