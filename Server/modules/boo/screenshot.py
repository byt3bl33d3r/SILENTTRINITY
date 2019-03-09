import base64

from core.module import Module
from core.utils import print_good
import datetime


class STModule(Module):
    def __init__(self):
        super().__init__()
        self.name = 'boo/screenshot'
        self.language = 'boo'
        self.description = 'Take a screenshot'
        self.author = '@davidtavarez'

    def payload(self):
        src = ''
        with open('modules/boo/src/screenshot.boo') as fp:  
            line = fp.readline()
            while line:
                src = '{}{}'.format(src,line)
                line = fp.readline()
        return src

    def process(self, result):
        b64_string = result.replace("\n", "").replace("\r", "")
        b64_string += "=" * ((4 - len(b64_string) % 4) % 4)
        b64_string = b64_string.encode()

        ba = bytes(b64_string)

        basename = "screenshot"
        suffix = '{}.{}'.format(datetime.datetime.now().strftime("%y%m%d_%H%M%S"), 'jpg')
        filename = "_".join([basename, suffix])

        with open(filename, "wb") as file:
            file.write(base64.decodebytes(ba))

        print_good("Screenshot was taken successfully: {}".format(filename))
