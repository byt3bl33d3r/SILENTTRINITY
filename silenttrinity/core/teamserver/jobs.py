import json
import os
import logging
import copy
import traceback
from silenttrinity.core.teamserver.job import Job


class Jobs:
    def __init__(self, session):
        self.session = session
        self.jobs = []
        self.jobs.append(Job(command=('CheckIn', [])))

    def next_job(self):
        try:
            return list(filter(lambda job: job.status == 'initialized', self.jobs))[-1]
        except IndexError:
            logging.error(f"No jobs available")

    def get_by_id(self, job_id):
        try:
            return list(filter(lambda job: job.id == job_id, self.jobs))[0]
        except IndexError:
            logging.error(f"Job with id {job_id} not found")

    def get(self, job_id=None):
        job = self.next_job()
        if job:
            try:
                job_payload = job.payload()
                job.status = 'started'
                return self.session.crypto.encrypt(job_payload)
            except Exception as e:
                self.jobs.remove(job)
                logging.error(f"Error generating payload for module '{job.module.name}': {e}")
                traceback.print_exc()

    def add(self, job):
        # We have to make a copy of the Job object here cause if we run the module on all sessions at once the status of the job
        # will be set to 'started' and on the next check in the next session won't grab it from the queue
        job_copy = copy.deepcopy(job)
        self.jobs.insert(0, job_copy)
        if job.command:
            self.session.logger.info(f"Tasked session to run command: {job.command[0]} args: {job.command[1]}")
        else:
            self.session.logger.info(f"Tasked session to run module: {job.module.name} args: {job.module.options}")

    def decrypt(self, job_id, data):
        job = self.get_by_id(job_id)
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
