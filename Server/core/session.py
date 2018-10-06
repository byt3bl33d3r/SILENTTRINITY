from prompt_toolkit.application import run_in_terminal
from time import time

class Session:
    def __init__(self, guid, remote_address, data):
        self.guid = guid
        self.address = remote_address
        self.data = data
        self.checkin_time = time()

    def add_job(self, job):
        self.queue.put(job)

    def checked_in(self):
        self.checkin_time = time()

    def last_check_in(self):
        return time() - self.checkin_time

    def __str__(self):
        return f"<Session guid: {self.guid} address: {self.address}>"
