import json
from io import BytesIO
from zipfile import ZipFile, ZIP_DEFLATED
from core.teamserver.job import Job
from core.teamserver.crypto import ECDHE


class Jobs:
    def __init__(self, session, pubkey):
        self.session = session
        self.crypto = ECDHE(pubkey)
        self.jobs = []

        self.jobs.append(Job(command=('CheckIn', {})))

    @property
    def public_key(self):
        return self.crypto.public_key

    def set_peer_public_key(self, pubkey):
        self.crypto = ECDHE(pubkey)

    def get_by_id(self, job_id):
        try:
            return list(filter(lambda job: job.id == job_id, self.jobs))[0]
        except IndexError:
            self.session.logger.error(f"Job with id {job_id} not found")

    def get(self):
        try:
            job = list(filter(lambda job: job.status == 'initialized', self.jobs))[-1]
            job.status = 'started'
            return self.crypto.encrypt(job.payload())
        except IndexError:
            pass

    def add(self, job):
        self.jobs.insert(0, job)
        if job.command:
            self.session.logger.info(f"Tasked session to run command: {job.command[0]} args: {job.command[1]}")
        else:
            self.session.logger.info(f"Tasked session to run module: {job.module.name} args: {job.module.options}")

    def results(self, job_id, data):
        decrypted_job = json.loads(self.crypto.decrypt(data))
        for job in self.jobs:
            if job.id == job_id:
                output = decrypted_job['result']
                if job.module:
                    self.session.logger.info(f"{self.session.guid} returned job result (id: {job_id}) \n {output}")
                    if hasattr(job.module, 'process'):
                        output = job.module.process(self, output)
                        self.session.logger.info(f"{self.session.guid} module '{job.module.name}' processed job results (id: {job_id}) \n {output}")
                elif job.command:
                    self.session.logger.info(f"{self.session.guid} returned command result (id: {job_id}): {output}")
                job.status = 'completed'

        return decrypted_job

    def get_encrypted_stage(self, comms):
        with open('./core/teamserver/data/stage.boo') as stage:
            with open(f"core/teamserver/comms/{comms}.boo") as comms:
                stage = stage.read()
                stage = stage.replace("PUT_COMMS_HERE", comms.read())

                with open('./core/teamserver/data/stage.zip', 'rb') as stage_file:
                    stage_file = BytesIO(stage_file.read())
                    with ZipFile(stage_file, 'a', compression=ZIP_DEFLATED, compresslevel=9) as zip_file:
                        zip_file.writestr("Main.boo", stage)

                    return self.crypto.encrypt(stage_file.getvalue())

    def __len__(self):
        return len(self.jobs)
