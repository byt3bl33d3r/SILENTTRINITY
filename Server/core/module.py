import abc


class Module:
    def __init__(self):
        self.name: str = 'module'
        self.description: str = ''
        self.author: str = ''
        self.options = {}

    @abc.abstractmethod
    def payload(self):
        raise NotImplementedError

    def process(self, result):
        print(result)
