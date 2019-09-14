from core.teamserver.module import Module


class STModule(Module):
    def __init__(self):
        self.name = 'boo/amsiPatch'
        self.language = 'boo'
        self.description = 'Disables AMSI in the current process'
        self.author = 'Patch by @_xpn & @rasta_mouse. Module by @byt3bl33d3r, @modexp, @daddycocoaman'
        self.references = []
        self.options = {}

    def payload(self):
        with open('core/teamserver/modules/boo/src/amsiPatch.boo', 'r') as module_src:
            src = module_src.read()
            return src
