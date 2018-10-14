import base64
import ntpath
import os

from core.module import Module
from core.utils import print_good


class STModule(Module):

    def __init__(self):
        Module.__init__(self)
        self.name = 'downloader'
        self.description = 'Download a file given a path.'
        self.author = '@davidtavarez'
        self.options = {
            'File': {
                'Description': 'The absolute path of the file.',
                'Required': True,
                'Value': None
            }
        }
        self.path = None

    def payload(self):
        if self.options['File']['Value'] is None:
            return None

        self.path = os.path.join(os.getcwd(), ntpath.basename(self.options['File']['Value']))

        with open('modules/src/downloader.py', 'r') as module_src:
            src = module_src.read()
            src = src.replace("FILE_PATH", self.options['File']['Value'])
            return src.encode()

    def process(self, result):
        b64_string = result.replace("\n", "").replace("\r", "")
        b64_string += "=" * ((4 - len(b64_string) % 4) % 4)
        b64_string = b64_string.encode()

        ba = bytes(b64_string)

        with open(self.path, "wb") as file:
            file.write(base64.decodebytes(ba))

        print_good("File was downloaded successfully: {}".format(self.path))
