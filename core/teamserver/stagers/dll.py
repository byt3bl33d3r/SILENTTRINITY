import logging
import uuid
from core.teamserver.crypto import gen_stager_psk
from core.teamserver.stager import Stager

class STStager(Stager):
    def __init__(self):
        self.name = 'dll'
        self.description = 'Generates a windows dll stager'
        self.suggestions = ''
        self.extension = 'dll'
        self.author = '@byt3bl33d3r'
        self.options = {}

    def generate(self, listener):
        with open('./core/teamserver/data/naga.dll', 'rb') as dll:
            guid = uuid.uuid4()
            psk = gen_stager_psk()

            return guid, psk, dll.read().decode('latin-1')
