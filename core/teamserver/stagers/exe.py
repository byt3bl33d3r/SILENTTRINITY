import logging
from core.teamserver.stager import Stager

class STStager(Stager):
    def __init__(self):
        self.name = 'exe'
        self.description = 'Generates a windows executable stager'
        self.suggestions = ''
        self.extension = 'exe'
        self.author = '@byt3bl33d3r'
        self.options = {}

    def generate(self, listener):
        with open('./core/teamserver/data/naga.exe', 'rb') as exe:
            return exe.read().decode('latin-1')
