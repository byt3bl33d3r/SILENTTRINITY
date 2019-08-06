import logging
from core.utils import print_bad, print_good, print_info

class ClientEventHandlers:
    def __init__(self, connection):
        self.connection = connection

    def stats_update(self, data):
        logging.debug(f"In stats_update event handler, got: {data}")
        self.connection.stats.LISTENERS = int(data['listeners']['active'])
        self.connection.stats.SESSIONS = int(data['sessions']['active'])
        self.connection.stats.USERS = data['users'].keys()

    def user_login(self, data):
        print_info(f"[{self.connection.alias}] {data}")

    def new_session(self, data):
        print_info(f"[{self.connection.alias}] {data}")

    def job_result(self, data):
        print_info(f"[{self.connection.alias}] {data['session']} returned job result (id: {data['id']})")
        print(data['output'])
