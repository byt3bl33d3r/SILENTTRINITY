from silenttrinity.core.utils import get_path_in_package
from silenttrinity.core.teamserver.module import Module


class STModule(Module):
    def __init__(self):
        self.name = 'boo/powershell'
        self.language = 'boo'
        self.description = 'Execute arbitrary PowerShell in an un-managed runspace'
        self.author = '@cobbr_io (Original C# Version), @byt3bl33d3r (Boolang Port)'
        self.references = ["System.Management.Automation"]
        self.options = {
            'Command': {
                'Description'   :   'PowerShell code to execute',
                'Required'      :   True,
                'Value'         :   '',
            },
            'OutString': {
                'Description'   :   'If true, appends Out-String to the PowerShellCode to execute',
                'Required'      :   False,
                'Value'         :   True,
            },
            'BypassLogging': {
                'Description'   :   'If true, bypasses ScriptBlock and Module logging',
                'Required'      :   False,
                'Value'         :   True,
            },
            'BypassAmsi': {
                'Description'   :   'If true, bypasses AMSI',
                'Required'      :   False,
                'Value'         :   True,
            }
        }

    def payload(self):
        with open(get_path_in_package('core/teamserver/modules/boo/src/powershell.boo'), 'r') as module_src:
            src = module_src.read()
            src = src.replace("POWERSHELL_SCRIPT", self.options["Command"]["Value"])
            src = src.replace("OUT_STRING", str(self.options["OutString"]["Value"]).lower())
            src = src.replace("BYPASS_LOGGING", str(self.options["BypassLogging"]["Value"]).lower())
            src = src.replace("BYPASS_AMSI", str(self.options["BypassAmsi"]["Value"]).lower())
            return src
