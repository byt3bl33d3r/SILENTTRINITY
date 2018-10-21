from time import time


class Session:
    def __init__(self, guid, remote_address, data):
        self.__guid = guid
        self.address = remote_address
        self.data = data
        self.checkin_time = time()

        self.__alias = None

    @property
    def guid(self):
        if self.__alias is not None:
            return self.__alias
        return self.__guid

    @guid.setter
    def guid(self, value):
        self.__alias = value

    def is_valid(self, guid):
        return self.__guid == guid or self.__alias == guid

    def add_job(self, job):
        self.queue.put(job)

    def checked_in(self):
        self.checkin_time = time()

    def last_check_in(self):
        return time() - self.checkin_time

    def __str__(self):
        return f"<Session guid: {self.guid} address: {self.address}>"
