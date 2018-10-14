class Module:
    def __init__(self):
        self.name = 'module'
        self.description = ''
        self.author = ''
        self.options = {}

    def process(self, result):
        print(result)