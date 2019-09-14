from core.teamserver.module import Module


class STModule(Module):
    def __init__(self):
        self.name = 'boo/bypassUACEventVwr'
        self.language = 'boo'
        self.description = 'Bypasses UAC by performing an image hijack on the .msc file extension'
        self.author = '@Daudau'
        self.references = []
        self.options = {
            'Command': {
                'Description': 'The command to execute with high integrity.',
                'Required': True,
                'Value': ""
            }
        }

    def payload(self):
        with open('core/teamserver/modules/boo/src/bypassUACEventVwr.boo', 'r') as module_src:
            src = module_src.read()
            src = src.replace('PAYLOAD', str(self.options['Command']['Value']))
            return src
