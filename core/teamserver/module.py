
class Module:
    def __init__(self):
        self.name = ''
        self.language = ''
        self.description = ''
        self.author = ''
        self.run_in_thread = True
        self.references = []
        self.options = {}

    def __getitem__(self, key):
        for k,_ in self.options.items():
            if k.lower() == key.lower():
                return self.options[k]['Value']

    def __setitem__(self, key, value):
        for k,_ in self.options.items():
            if k.lower() == key.lower():
                self.options[k]['Value'] = value

    def __iter__(self):
        yield ("name", self.name)
        yield ("language", self.language)
        yield ("description", self.description)
        yield ("author", self.author)
        yield ("references", self.references)
        yield ("options", self.options)
