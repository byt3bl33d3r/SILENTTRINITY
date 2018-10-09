
class STModule:
    def __init__(self):
        self.name = 'internalmonologue'
        self.description = 'Executes the Internal Monologue attack.\nIf admin, this will give you the Net-NTLMv1 hashes of all logged on users'
        self.author = '@byt3bl33d3r'
        self.options = {
            'Impersonate': {
                'Description'   :   'Specifies whether to try to impersonate all other available users or not',
                'Required'      :   False,
                'Value'         :   True
            },
            'Threads': {
                'Description'   :   'Specifies whether to try to locate tokens to impersonate from threads or not',
                'Required'      :   False,
                'Value'         :   False,
            },
            'Downgrade': {
                'Description'   :   'Specifies whether to perform an NTLM downgrade or not',
                'Required'      :   False,
                'Value'         :   True,
            },
            'Restore': {
                'Description'   :   'Specifies whether to restore the original values from before the NTLM downgrade or not',
                'Required'      :   False,
                'Value'         :   True,
            },
            'Challenge': {
                'Description'   :   'Specifies the NTLM challenge to be used. An 8-byte long value in ascii-hex representation',
                'Required'      :   False,
                'Value'         :   "1122334455667788",
            },
            'Verbose': {
                'Description'   :   'Specifies whether print verbose output or not',
                'Required'      :   False,
                'Value'         :   True,
            }
        }

    def payload(self):
        with open('modules/src/internalmonologue.py', 'r') as module_src:
            src = module_src.read()
            src = src.replace("impersonate=", f"impersonate={self.options['Impersonate']['Value']}")
            src = src.replace("threads=", f"threads={self.options['Threads']['Value']}")
            src = src.replace("downgrade=", f"downgrade={self.options['Downgrade']['Value']}")
            src = src.replace("restore=", f"restore={self.options['Restore']['Value']}")
            src = src.replace("challenge=", f"challenge=\"{self.options['Challenge']['Value']}\"")
            src = src.replace("verbose=", f"verbose={self.options['Verbose']['Value']}")
            return src.encode()
