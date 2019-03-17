class STModule:
    def __init__(self):
        self.name = 'ipy/rubeus'
        self.language = 'ipy'
        self.description = 'Everything related to Kerberos in an Active Directory environment (kerberoasting etc.) using https://github.com/GhostPack/Rubeus'
        self.author = 'maaaaz'
        self.options = {
            'Command': {
                'Description': 'The Rubeus command to use (by default "kerberoast")',
                'Required': True,
                'Value': "kerberoast"
            },
        }

    def payload(self):
        with open('modules/ipy/src/rubeus.py', 'r') as module_src:
            src = module_src.read()
            src = src.replace('COMMAND', self.options['Command']['Value'])
            return src