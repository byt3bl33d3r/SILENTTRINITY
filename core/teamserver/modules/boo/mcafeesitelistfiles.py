from core.teamserver.module import Module


class STModule(Module):
    def __init__(self):
        self.name = 'boo/mcafeesitelistfiles'
        self.language = 'boo'
        self.description = 'Find McAfee SiteList.xml Files'
        self.author = '@Daudau'
        self.references = []
        self.options = {}

    def payload(self):
        with open('core/teamserver/modules/boo/src/mcafeesitelistfiles.boo', 'r') as module_src:
            src = module_src.read()
            return src
