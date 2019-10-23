import uuid
from silenttrinity.core.teamserver.crypto import gen_stager_psk
from silenttrinity.core.teamserver.stager import Stager
from silenttrinity.core.utils import get_path_in_package


class STStager(Stager):
    def __init__(self):
        self.name = 'exe'
        self.description = 'Generates a windows executable stager'
        self.suggestions = ''
        self.extension = 'exe'
        self.author = '@byt3bl33d3r'
        self.options = {}

    def generate(self, listener):
        with open(get_path_in_package('core/teamserver/data/naga.exe'), 'rb') as exe:
            guid = uuid.uuid4()
            psk = gen_stager_psk()

            return guid, psk, exe.read().decode('latin-1')
