import clr

clr.AddReference("System.Management")
clr.AddReference("System.Management.Automation")

from System import Guid, Environment, String
from System.Management.Automation import PSCredential, PowerShell
from System.Management.Automation.Runspaces import WSManConnectionInfo, RunspaceFactory
from System.Security import SecureString
from System.Security.Principal import WindowsIdentity, WindowsPrincipal, WindowsBuiltInRole

def IsHighIntegrity():
    identity = WindowsIdentity.GetCurrent()
    principal = WindowsPrincipal(identity)
    return principal.IsInRole(WindowsBuiltInRole.Administrator)

def StringToSecureString(string):
    SecurePassword = SecureString()
    for c in string:
        SecurePassword.AppendChar(c)
    return SecurePassword

def start_ps_remoting(target, payload, username='', password='', domain='', add_trusted_hosts=False):
    try:
        if add_trusted_hosts:
            if IsHighIntegrity():
                print "[*] Adding {} to TrustedHosts\n".format(target)
                with PowerShell.Create() as ps:
                    ps.AddCommand("Set-Item")
                    ps.AddParameter("Path", "WSMan:\\localhost\\Client\\TrustedHosts")
                    ps.AddParameter("Value", target)
                    ps.AddParameter("Force")
                    ps.Invoke()
            else:
                print "[-] Not in high integrity process, cannot add target to TrustedHosts"

        remoteCredential = None
        if username and password and domain:
            print "[*] Using credentials for {}\\{} to authenticate to {}".format(domain, username, target)
            remoteCredential = PSCredential("{}\\{}".format(domain, username), StringToSecureString(password))

        connectionInfo = WSManConnectionInfo(
            False,
            target,
            5985,
            "/wsman",
            "http://schemas.microsoft.com/powershell/Microsoft.PowerShell",
            remoteCredential
        )

        rs = RunspaceFactory.CreateRunspace(connectionInfo)

        with PowerShell.Create() as ps:
            rs.Open()
            ps.Runspace = rs

            ps_code = "Start-Job {{{}}}".format(payload)
            ps.AddScript(ps_code)
            ps.BeginInvoke()
    except Exception as e:
        print str(e)
    finally:
        if add_trusted_hosts and IsHighIntegrity():
            print "\n[*] Removing {} from TrustedHosts".format(target)
            with PowerShell.Create() as ps:
                ps.AddCommand("Set-Item")
                ps.AddParameter("Path", "WSMan:\\localhost\\Client\\TrustedHosts")
                ps.AddParameter("Value", "")
                ps.AddParameter("Force")
                ps.Invoke()

payload = """
PAYLOAD
"""

start_ps_remoting(
    target="TARGET",
    payload=payload,
    username="USERNAME",
    password="PASSWORD",
    domain="DOMAIN",
    add_trusted_hosts=TRUSTED_HOSTS,
)
