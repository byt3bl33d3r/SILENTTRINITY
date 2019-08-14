import logging
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
            return dll.read().decode('latin-1')
