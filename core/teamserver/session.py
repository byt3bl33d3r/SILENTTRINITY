import json
import logging
import os
import uuid
from time import time
from io import BytesIO
from zipfile import ZipFile, ZIP_DEFLATED
from core.teamserver.jobs import Jobs
from core.teamserver.comms.utils import gen_stager_code
from core.teamserver.crypto import ECDHE


class Session:
    def __init__(self, guid, psk):
        self._guid = str(guid)
        self._alias = str(guid)
        self._info = None
        self.address = None
        self.checkin_time = None
        self.crypto = ECDHE(psk=psk)
        self.jobs = Jobs(self)

        self.logger = logging.getLogger(f"session:{str(self._guid)}")
        self.logger.propagate = False
        self.logger.setLevel(logging.DEBUG)

        try:
            os.mkdir(f"./data/logs/{self._guid}")
        except FileExistsError:
            pass

        formatter = logging.Formatter('%(asctime)s - %(message)s')
        fh = logging.FileHandler(f"./data/logs/{self._guid}/{self._guid}.log", encoding='UTF-8')
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(formatter)
        self.logger.addHandler(fh)

    @property
    def guid(self):
        if self._alias is not None:
            return self._alias
        return self._guid

    @guid.setter
    def guid(self, value):
        self._alias = value

    @property
    def info(self):
        return self._info

    @info.setter
    def info(self, value):
        # This is temporary, ideally I'd like to be able to change c2 channels on the fly in the future :)
        self._info = value
        self._info["Jobs"] = len(self._info['Jobs'])
        self._info["C2Channels"] = [channel['Name'] for channel in self._info['Channels']]
        self._info["CallBackUrls"] = [channel['CallBackUrls'] for channel in self._info['Channels']]
        del self._info["Channels"]

    def checked_in(self):
        self.checkin_time = time()

    def last_check_in(self):
        return time() - self.checkin_time

    def gen_encrypted_stage(self, comms):
        stage = gen_stager_code(comms)
        with open('./core/teamserver/data/stage.zip', 'rb') as stage_file:
            stage_file = BytesIO(stage_file.read())
            with ZipFile(stage_file, 'a', compression=ZIP_DEFLATED, compresslevel=9) as zip_file:
                zip_file.writestr("Main.boo", stage)

            return self.crypto.encrypt(stage_file.getvalue())

    def __str__(self):
        return f"<Session {self._guid}{f' alias: {self._alias}' if self._alias else ''}>"

    def __hash__(self):
        return hash(self.guid)
    
    def __iter__(self):
        yield ('guid', str(self._guid))
        yield ('alias', str(self._alias))
        yield ('address', self.address)
        yield ('info', self.info)
        yield ('lastcheckin', self.last_check_in())

    def __eq__(self, other):
        if type(other) == uuid.UUID:
            return self._guid == str(other)
        elif type(other) == str:
            return str(self._guid) == other or str(self._alias) == other
        elif isinstance(other, type(self)):
            return self._guid == other.guid

        return NotImplemented
