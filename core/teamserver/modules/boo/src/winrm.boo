import System
import System.Management.Automation
import System.Management.Automation.Runspaces
import System.Security
import System.Security.Principal

public static def IsHighIntegrity() as bool:
    identity = WindowsIdentity.GetCurrent()
    principal = WindowsPrincipal(identity)
    return principal.IsInRole(WindowsBuiltInRole.Administrator)

public static def StringToSecureString(passw as string):
    SecurePassword = SecureString()
    for c in passw:
        SecurePassword.AppendChar(c)
    return SecurePassword

public static def StartPSRemoting(target as string, payload as string, username as string, password as string, domain as string, add_trusted_hosts as bool) as void:
    try:
        if add_trusted_hosts:
            if IsHighIntegrity():
                print "[*] Adding $(target) to TrustedHosts\n"
                ps = PowerShell.Create()
                ps.AddCommand("Set-Item")
                ps.AddParameter("Path", "WSMan:\\localhost\\Client\\TrustedHosts")
                ps.AddParameter("Value", target)
                ps.AddParameter("Force")
                ps.Invoke()
            else:
                print "[-] Not in high integrity process, cannot add target to TrustedHosts"

        remoteCredential = null
        if username and password and domain:
            print "[*] Using credentials for $(domain)\\$(username) to authenticate to $(target)"
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

        pipe = rs.CreatePipeline(payload.Trim())
        pipe.InvokeAsync()
    except e as Exception:
        print e
    ensure:
        if add_trusted_hosts and IsHighIntegrity():
            print "\n[*] Removing $(target) from TrustedHosts"
            ps = PowerShell.Create()
            ps.AddCommand("Set-Item")
            ps.AddParameter("Path", "WSMan:\\localhost\\Client\\TrustedHosts")
            ps.AddParameter("Value", "")
            ps.AddParameter("Force")
            ps.Invoke()

public static def Main():
    payload = `
PAYLOAD
`

    StartPSRemoting(
        target="TARGET",
        payload=payload,
        username="USERNAME",
        password="PASSWORD",
        domain="DOMAIN",
        add_trusted_hosts=TRUSTED_HOSTS
    )
