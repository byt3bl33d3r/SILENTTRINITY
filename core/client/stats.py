
class ClientConnectionStats:
    def __init__(self):
        self.USERS = []
        self.IPS = []
        self.LISTENERS = {}
        self.SESSIONS = {}
        self.CONNECTED = False
        self.STAGERS = {}
