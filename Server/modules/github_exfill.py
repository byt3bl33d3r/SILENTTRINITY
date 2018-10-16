class STModule:
    def __init__(self):
        self.name = 'shell'
        self.description = 'Runs a shell command'
        self.author = '@byt3bl33d3r'
        self.options = {
            'Command': {
                'Description'   :   'The ShellCommand to execute, including any arguments',
                'Required'      :   True,
                'Value'         :   ''
            },
        }

    def payload(self):
        with open('modules/src/shell.py', 'r') as module_src:
            src = module_src.read()
            src = src.replace("COMMAND_TO_RUN", self.options['Command']['Value'])
            src = src.replace("PATH", self.options['Path']['Value'])
            src = src.replace("USERNAME", self.options['Username']['Value'])
            src = src.replace("DOMAIN", self.options['Domain']['Value'])
            src = src.replace("PASSWORD", self.options['Password']['Value'])
            return src.encode()
