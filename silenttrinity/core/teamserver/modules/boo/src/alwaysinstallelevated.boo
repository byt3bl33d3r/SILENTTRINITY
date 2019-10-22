/*
    This module is adapted from SharpUp (https://github.com/GhostPack/SharpUp)
*/
import System
import System.Security.Principal
import Microsoft.Win32


public static def IsHighIntegrity() as bool:
    identity = WindowsIdentity.GetCurrent()
    principal = WindowsPrincipal(identity)
    return principal.IsInRole(WindowsBuiltInRole.Administrator)


public static def isAdmin() as bool:
    identity as WindowsIdentity = WindowsIdentity.GetCurrent()
    if (identity != null):
        principal as WindowsPrincipal = WindowsPrincipal(identity)
        list = principal.UserClaims
        for c in list:
            if c.Value.Contains("S-1-5-32-544"):
                return true
    return false


public static def GetRegValue(hive as string, path as string, value as string) as string:
    // returns a single registry value under the specified path in the specified hive
    regKeyValue as string
    if hive == "HKCU":
        regKey = Registry.CurrentUser.OpenSubKey(path)
        if regKey:
            regKeyValue = String.Format("{0}", regKey.GetValue(value))
        return regKeyValue
    else: // HKLM
        regKey = Registry.LocalMachine.OpenSubKey(path)
        if regKey:
            regKeyValue = String.Format("{0}", regKey.GetValue(value))
        return regKeyValue


public static def GetAlwaysInstallElevated() as void :
    print "\r\n=== AlwaysInstallElevated Registry Keys ===\r\n"

    AlwaysInstallElevatedHKLM as string = GetRegValue("HKLM", "Software\\\\Policies\\\\Microsoft\\\\Windows\\\\Installer", "AlwaysInstallElevated")
    AlwaysInstallElevatedHKCU as string = GetRegValue("HKCU", "Software\\\\Policies\\\\Microsoft\\\\Windows\\\\Installer", "AlwaysInstallElevated")

    if AlwaysInstallElevatedHKLM:
        print "  HKLM\\Software\\Policies\\Microsoft\\Windows\\Installer\\AlwaysInstallElevated:    " + AlwaysInstallElevatedHKLM

    if AlwaysInstallElevatedHKCU:
        print "  HKCU\\Software\\Policies\\Microsoft\\Windows\\Installer\\AlwaysInstallElevated:    " + AlwaysInstallElevatedHKCU


public static def Main():
    if IsHighIntegrity():
        print "[*] Already in high integrity, no need to privesc!"
    elif isAdmin():
        print "[*] In medium integrity but user is a local administrator - UAC can be bypassed."
    else:
        GetAlwaysInstallElevated()
