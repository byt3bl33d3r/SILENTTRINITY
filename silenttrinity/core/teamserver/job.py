import json
from silenttrinity.core.utils import gen_random_string


class Job:
    def __init__(self, command=None, module=None):
        self.id = gen_random_string()
        self.status = 'initialized'
        self.command = command
        self.module = module

    def payload(self):
        payload = {'id': self.id}

        if self.command:
            payload['cmd'] = self.command[0]
            payload['args'] = {'args': self.command[1]}

        elif self.module:
            payload['cmd'] = "CompileAndRun"
            payload['args'] = {
                "source": self.module.payload(),
                "references": self.module.references,
                "run_in_thread": self.module.run_in_thread if hasattr(self.module, 'run_in_thread') else True
            }

        return json.dumps(payload).encode()
    
    def __repr__(self):
        return f"<Job id:{self.id} status: {self.status} command:{self.command} module: {self.module}>"
