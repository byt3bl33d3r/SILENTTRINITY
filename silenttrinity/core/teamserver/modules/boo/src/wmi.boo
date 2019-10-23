import System
import System.Management

# https://docs.microsoft.com/en-us/dotnet/api/system.management.managementobject.invokemethod?view=netframework-4.7.2

public static def WMIExec(host as string, command as string, domain as string, username as string, password as string) as string:
    options = ConnectionOptions()
    options.EnablePrivileges = true
    if not domain and not username and not password:
        options.Impersonation = ImpersonationLevel.Impersonate
        options.Authentication = AuthenticationLevel.Default
    else:
        options.Username = "$(domain)\\$(username)"
        options.Password = password

    network_scope = "\\\\$(host)\\root\\cimv2"
    scope = ManagementScope(network_scope, options)
    win32_process = ManagementClass(scope, ManagementPath("Win32_Process"), null)

    inParams = win32_process.GetMethodParameters("Create")
    inParams["CommandLine"] = command

    out = win32_process.InvokeMethod("Create", inParams, null)
    print out["ReturnValue"], out["processId"]

public static def Main():
    WMIExec("TARGET", "COMMAND", domain="DOMAIN", username="USERNAME", password="PASSWORD")
