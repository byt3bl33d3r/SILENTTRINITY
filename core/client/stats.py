
class ClientSessionStats:
    def __init__(self, teamservers):
        self.teamservers = teamservers

    @property
    def LISTENERS(self):
        listeners = 0
        for ts in self.teamservers:
            listeners += ts.stats.LISTENERS
        return listeners

    @property
    def SESSIONS(self):
        sessions = 0
        for ts in self.teamservers:
            sessions += ts.stats.SESSIONS
        return sessions

    @property
    def USERS(self):
        users = set()
        for ts in self.teamservers:
            for user in ts.stats.USERS:
                users.add(user)
        return list(users)

class ClientConnectionStats:
    def __init__(self):
        self.LISTENERS = 0
        self.USERS = []
        self.SESSIONS = 0
        self.CONNECTED = False
