import os
from base64 import b64encode
from shlex import split
from core.teamserver.module import Module

class STModule(Module):
    def __init__(self):
        self.name = 'execution/sharpcradle'
        self.language = 'boo'
        self.description = 'Execute a .NET assembly in memory'
        self.author = '@hackabean'
        self.references = []
        self.options = {
            'Assembly': {
                'Description'   :   'Path to assembly',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Arguments': {
                'Description'   :   'Arguments to pass to the assembly on runtime',
                'Required'      :   False,
                'Value'         :   ""
            }
        }

    def payload(self):
        with open('core/teamserver/modules/boo/src/sharpcradle.boo', 'r') as module_src:
            src = module_src.read()
            return src