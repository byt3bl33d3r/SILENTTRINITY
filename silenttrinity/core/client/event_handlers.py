import logging
from silenttrinity.core.utils import print_bad, print_good, print_info

class ClientEventHandlers:
    def __init__(self, connection):
        self.connection = connection

    def stats_update(self, data):
        logging.debug(f"In stats_update event handler, got: {data}")
        self.connection.stats.LISTENERS = data['listeners']
        self.connection.stats.SESSIONS = data['sessions']
        self.connection.stats.USERS = data['users']
        self.connection.stats.IPS = data['ips']

    def loadables_update(self, data):
        for ctx, loadables in data.items():
            for lctx in self.connection.contexts:
                if lctx.name == ctx:
                    lctx.available = loadables

    def user_login(self, data):
        print_info(f"[{self.connection.alias}] {data}")
    
    def session_staged(self, data):
        print_info(f"[{self.connection.alias}] {data}")

    def new_session(self, data):
        print_info(f"[{self.connection.alias}] {data}")

    def job_result(self, data):
        print_info(f"[{self.connection.alias}] {data['session']} returned job result (id: {data['id']})")
        print(data['output'])
