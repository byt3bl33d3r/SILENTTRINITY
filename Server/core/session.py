import json
import logging
from core.job import Job
from core.crypto import ECDHE
from uuid import UUID
from time import time
from queue import Queue, Empty
from io import BytesIO
from zipfile import ZipFile, ZIP_DEFLATED


class Session:
    def __init__(self, guid, remote_address, pubkey_xml):
        self.guid = guid
        self.address = remote_address
        self.data = None
        self.checkin_time = None
        self.crypto = ECDHE(pubkey_xml)
        self.jobs = Queue()

        self.logger = logging.getLogger(str(guid))
        self.logger.propagate = False
        self.logger.setLevel(logging.DEBUG)

        formatter = logging.Formatter('%(asctime)s - %(message)s')
        fh = logging.FileHandler(f"./logs/{guid}.log", encoding='UTF-8')
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(formatter)

        self.logger.addHandler(fh)

        self.add_job(Job(command=('checkin', '')))

    @property
    def public_key(self):
        return self.crypto.public_key

    def set_peer_public_key(self, pubkey_xml):
        self.crypto = ECDHE(pubkey_xml)

    def add_job(self, job):
        self.jobs.put(job)
        if job.command:
            self.logger.info(f"Tasked session to run command: {job.command[0]} args: {job.command[1]}")
        else:
            self.logger.info(f"Tasked session to run module: {job.module.name} args: {job.module.options}")

    def get_job(self):
        try:
            job = self.jobs.get(block=False)
            return self.crypto.encrypt(job.payload())
        except Empty:
            pass

    def checked_in(self):
        self.checkin_time = time()

    def last_check_in(self):
        return time() - self.checkin_time

    def set_session_info(self, data):
        self.data = json.loads(self.crypto.decrypt(data))['result']

    def get_encrypted_stage(self):
        with open('data/stage.zip', 'rb') as stage_file:
            stage_file = BytesIO(stage_file.read())
            with ZipFile(stage_file, 'a', compression=ZIP_DEFLATED, compresslevel=9) as zip_file:
                zip_file.write("data/stage.py", arcname="Main.py")

            return self.crypto.encrypt(stage_file.getvalue())

    def __str__(self):
        return f"<Session {self.address} ({self.guid})>"

    def __hash__(self):
        return hash(self.guid)

    def __eq__(self, other):
        if type(other) == UUID:
            return self.guid == other
        elif type(other) == str:
            return str(self.guid) == other
        elif isinstance(other, type(self)):
            return self.guid == other.guid

        return NotImplemented
