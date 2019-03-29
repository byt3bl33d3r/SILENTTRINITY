import json
import logging
import os
from core.jobs import Jobs
from uuid import UUID
from time import time


class Session:
    def __init__(self, guid, remote_address, pubkey):
        self.__alias = str(guid)
        self.__guid = guid
        self.address = remote_address
        self.info = None
        self.checkin_time = None

        try:
            os.mkdir(f"./logs/{guid}")
        except FileExistsError:
            pass

        self.logger = logging.getLogger(str(guid))
        self.logger.propagate = False
        self.logger.setLevel(logging.DEBUG)

        formatter = logging.Formatter('%(asctime)s - %(message)s')
        fh = logging.FileHandler(f"./logs/{guid}/{guid}.log", encoding='UTF-8')
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(formatter)

        self.logger.addHandler(fh)

        self.jobs = Jobs(self, pubkey)

    @property
    def guid(self):
        if self.__alias is not None:
            return self.__alias
        return self.__guid

    @guid.setter
    def guid(self, value):
        self.__alias = value

    def checked_in(self):
        self.checkin_time = time()

    def last_check_in(self):
        return time() - self.checkin_time

    def set_info(self, data):
        self.logger.info(f"New session {self.guid} connected! ({self.address})")
        self.info = json.loads(self.jobs.crypto.decrypt(data))['result']

    def __str__(self):
        return f"<Session {self.address} ({self.guid}) Jobs: {len(self.jobs)}>"

    def __hash__(self):
        return hash(self.guid)

    def __eq__(self, other):
        if type(other) == UUID:
            return self.__guid == other
        elif type(other) == str:
            return str(self.guid) == other or str(self.__alias) == other
        elif isinstance(other, type(self)):
            return self.__guid == other.guid

        return NotImplemented
