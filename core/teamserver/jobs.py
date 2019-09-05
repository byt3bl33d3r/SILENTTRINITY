import json
import os
import logging
from core.teamserver.job import Job


class Jobs:
    def __init__(self, session):
        self.session = session
        self.jobs = []
        self.jobs.append(Job(command=('CheckIn', {})))

    def find(self, job_id=None):
        try:
            if job_id:
                job = list(filter(lambda job: job.id == job_id, self.jobs))[0]
            else:
                job = list(filter(lambda job: job.status == 'initialized', self.jobs))[-1]
            return job
        except IndexError:
            if job_id:
                logging.error(f"Job with id {job_id} not found")
            else:
                logging.error(f"No jobs available")

    def get(self, job_id=None):
        job = self.find()
        if job:
            job.status = 'started'
            return self.session.crypto.encrypt(job.payload())

    def add(self, job):
        self.jobs.insert(0, job)
        if job.command:
            self.session.logger.info(f"Tasked session to run command: {job.command[0]} args: {job.command[1]}")
        else:
            self.session.logger.info(f"Tasked session to run module: {job.module.name} args: {job.module.options}")

    def decrypt(self, job_id, data):
        job = self.find(job_id)
        decrypted_job = json.loads(self.session.crypto.decrypt(data))
        output = decrypted_job['result']
        if job.module:
            if hasattr(job.module, 'process') and not decrypted_job['error'] == True:
                output = job.module.process(self, output)
                self.session.logger.info(f"{self.session.guid} module '{job.module.name}' processed job results (id: {job_id}) \n {output}")
            else:
                self.session.logger.info(f"{self.session.guid} returned job result (id: {job_id}) \n {output}")
        elif job.command:
            self.session.logger.info(f"{self.session.guid} returned command result (id: {job_id}): {output}")

        #job.status = 'completed'
        return decrypted_job, output

    def __len__(self):
        return len(self.jobs)

    def __repr__(self):
        return f"<Jobs ({len(self.jobs)})>"
