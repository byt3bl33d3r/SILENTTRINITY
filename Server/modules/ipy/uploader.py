import os
import base64
from core.module import Module


class STModule(Module):
    def __init__(self):
        super().__init__()
        self.name = 'ipy/uploader'
        self.language = 'ipy'
        self.description = 'Upload a file to a destination path.'
        self.author = '@davidtavarez, @byt3bl33d3r'
        self.options = {
            'File': {
                'Description': 'The absolute path of the file.',
                'Required': True,
                'Value': None
            },
            'Destination': {
                'Description': 'The destination path of the file.',
                'Required': False,
                'Value': "C:\\\\WINDOWS\\\\Temp\\\\"
            }
        }

    def payload(self):
        if self.options['File']['Value'] is None:
            return None

        if not os.path.exists(self.options['File']['Value']):
            from core.utils import print_bad
            print_bad("Selected file do not exists.")
            return None

        with open(self.options['File']['Value'], "rb") as file:
            encoded_string = base64.b64encode(file.read()).decode("utf-8")

        with open('modules/ipy/src/uploader.py', 'r') as module_src:
            src = module_src.read()
            src = src.replace("FILENAME", os.path.basename(self.options['File']['Value']))
            src = src.replace("DESTINATION", self.options['Destination']['Value'])
            src = src.replace("DATA", encoded_string)
            return src
