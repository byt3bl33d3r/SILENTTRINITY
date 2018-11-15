from prompt_toolkit.application import run_in_terminal
from time import time


class Session:
    def __init__(self, guid, remote_address):
        self.guid = guid
        self.queue = []
        self.address = remote_address
        self.data = {}
        self.checkin_time = time()

        #self.add_job(Job())

    def add_job(self, job):
        self.queue.append(job)

    def get_job(self, data):
        try:
            job = self.queue[-1]
            job.set_public_key(data)
            return job.json()
        except IndexError:
            return None

    def get_job_by_id(self, id):
        for job in self.queue:
            if job.id == id:
                return job

    def remove_job(self, id):
        queue_copy = self.queue[:]

    def checked_in(self):
        self.checkin_time = time()

    def last_check_in(self):
        return time() - self.checkin_time

    def __str__(self):
        return f"<Session guid: {self.guid} address: {self.address}>"
