from core.teamserver.module import Module


class STModule(Module):
    def __init__(self):
        self.name = 'boo/seatbelt'
        self.language = 'boo'
        self.description = 'Performs a number of security oriented host-survey "safety checks" relevant from both offensive and defensive security perspectives.'
        self.author = '@harmj0y (original C# version), @byt3bl33d3r (Boolang port)'
        self.references = ["System.Web.Extensions", "System.Management"]
        self.options = {
            'Arguments': {
                'Description'   :   'Seatbelt arguments',
                'Required'      :   True,
                'Value'         :   ""
            }
        }

    def payload(self):
        with open('core/teamserver/modules/boo/src/seatbelt.boo') as module_src:
            src = module_src.read()
            src = src.replace('ARGS_GO_HERE', self.options['Arguments']['Value'])
            return src
