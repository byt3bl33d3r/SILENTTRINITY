class STModule:
    def __init__(self):
        self.name = 'boo/screenshot'
        self.language = 'boo'
        self.description = 'Take a screenshot'
        self.author = '@davidtavarez'

    def payload(self):
        src = ''
        with open('modules/boo/src/screenshot.boo') as fp:  
            line = fp.readline()
            while line:
                src = '{}{}'.format(src,line)
                line = fp.readline()
        return src

