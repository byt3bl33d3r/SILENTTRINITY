import json
from core.utils import gen_random_string


class Job:
    def __init__(self, module):
        self.id = gen_random_string()
        self.module = module

    def payload(self):
        payload = {
            'id': self.id,
            'cmd': 'run_ipy_script' if self.module.language == 'ipy' else 'run_boo_script',
            'args': self.module.payload()
        }

        return json.dumps(payload).encode()
