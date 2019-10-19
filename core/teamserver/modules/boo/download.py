import gzip
import logging
import json
from datetime import datetime
from base64 import b64decode
from core.teamserver.module import Module


class STModule(Module):
    def __init__(self):
        self._new_dmp_file = True  # This sucks but its currently the only way to keep track if we want a new file

        self.name = 'boo/download'
        self.language = 'boo'
        self.description = 'Downloads the specified file.'
        self.author = 'ad0nis'
        self.references = []
        self.options = {
            'File': {
                'Description': 'The Path of the file to download',
                'Required': True,
                'Value': r""
            }
        }

    def payload(self):
        with open('core/teamserver/modules/boo/src/download.boo', 'r') as module_src:
            src = module_src.read()
            src = src.replace('FILE_PATH', self.options['File']['Value'])
            return src

    def process(self, context, output):
        if self._new_dmp_file == True:
            self._new_dmp_file = False
            self.gzip_file = f"./data/logs/{context.session.guid}/download_{datetime.now().strftime('%Y_%m_%d_%H%M%S')}.gz"
            self.decompressed_file = f"./data/logs/{context.session.guid}/download_{datetime.now().strftime('%Y_%m_%d_%H%M%S')}.bin"

        try:
            file_chunk = output['data']
            with open(self.gzip_file, 'ab+') as reassembled_gzip_file:
                reassembled_gzip_file.write(b64decode(file_chunk))

            if output['current_chunk_n'] == (output['chunk_n'] + 1):
                try:
                    with open(self.decompressed_file, 'wb') as reassembled_file:
                        with gzip.open(self.gzip_file) as compressed_mem_dump:
                            reassembled_file.write(compressed_mem_dump.read())
                except Exception as e:
                    logging.error(f"Error decompressing re-assembled memory dump: {e}")
                
                self._new_dmp_file = True
                return f"Saved file to {self.decompressed_file}!"

            else:
                return f"Processed chunk {output['current_chunk_n']}/{output['chunk_n'] + 1}"
        except TypeError:
            return output
