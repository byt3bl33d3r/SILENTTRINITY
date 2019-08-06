import logging

class ServerResponse:
    def __init__(self, response, connection):
        self.raw = response
        self.connection = connection

        for k,v in response.items():
            setattr(self, k, v)
