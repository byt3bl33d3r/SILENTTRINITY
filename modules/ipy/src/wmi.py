import clr
clr.AddReference("System.Management")
from System.Management import ConnectionOptions, ManagementScope, ManagementClass, ManagementPath, AuthenticationLevel, ImpersonationLevel

# https://mail.python.org/pipermail/ironpython-users/2010-April/012545.html
# https://docs.microsoft.com/en-us/dotnet/api/system.management.managementobject.invokemethod?view=netframework-4.7.2


def wmiexec(host, command, domain="", username="", password=""):
    options = ConnectionOptions()
    options.EnablePrivileges = True
    if not domain and not username and not password:
        options.Impersonation = ImpersonationLevel.Impersonate
        options.Authentication = AuthenticationLevel.Default
    else:
        options.Username = "{}\\{}".format(domain, username)
        options.Password = password

    network_scope = "\\\\{}\\root\\cimv2".format(host)
    scope = ManagementScope(network_scope, options)
    win32_process = ManagementClass(scope, ManagementPath("Win32_Process"), None)

    inParams = win32_process.GetMethodParameters("Create")
    inParams["CommandLine"] = command

    out = win32_process.InvokeMethod("Create", inParams, None)
    print out["ReturnValue"], out["processId"]

wmiexec("HOST", "COMMAND", domain="DOMAIN", username="USERNAME", password="PASSWORD")
