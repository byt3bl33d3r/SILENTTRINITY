import json
from core.utils import gen_random_string


class Job:
    def __init__(self, command=None, module=None):
        self.id = gen_random_string()
        self.status = 'initialized'
        self.command = command
        self.module = module

    def payload(self):
        payload = {'id': self.id}

        if self.command:
            payload['cmd'], payload['args'] = self.command

        elif self.module:
            payload['cmd'] = "CompileAndRun"
            payload['args'] = {"source": self.module.payload(), "references": self.module.references}

        return json.dumps(payload).encode()
