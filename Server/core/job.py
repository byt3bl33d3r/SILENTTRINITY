import gzip
import json
from io import BytesIO
from core.utils import gen_random_string
from base64 import b64encode, b64decode
from secrets import token_bytes


class Job:
    def __init__(self, module):
        self.id = gen_random_string()
        self.module = module

    def encode(self):
        payload = b64encode(self.module.payload()).decode()
        junk = {gen_random_string(): b64encode(token_bytes(5)).decode()}

        job = {'id': self.id, 'command': 'run_script', 'data': payload}
        stream = BytesIO()
        with gzip.open(stream, 'wb') as gzip_stream:
            gzip_stream.write(json.dumps(job).encode())

        malform = bytearray(stream.getvalue())
        malform[:2] = token_bytes(2)

        junk['data'] = b64encode(bytes(malform)).decode()

        return junk

    @staticmethod
    def decode(response):
        data = b64decode(response['data'])
        good_gzip = bytearray(data)
        good_gzip[:2] = b"\x1f\x8b"

        stream = BytesIO(bytes(good_gzip))

        with gzip.open(stream, 'rb') as f:
            return json.loads(f.read())
