class STModule:
    def __init__(self):
        self.name = 'powershell'
        self.description = 'Execute arbitrary PowerShell in an un-managed runspace'
        self.author = '@byt3bl33d3r'
        self.options = {
            'Command': {
                'Description'   :   'The ShellCommand to execute, including any arguments',
                'Required'      :   True,
                'Value'         :   ''
            }
        }

    def payload(self):
        with open('modules/src/powershell.py', 'r') as module_src:
            src = module_src.read()
            src = src.replace("COMMAND_TO_RUN", self.options["Command"]["Value"])

            return src.encode()
