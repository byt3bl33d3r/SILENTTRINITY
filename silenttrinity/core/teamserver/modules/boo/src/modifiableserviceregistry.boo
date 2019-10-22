/*
    This module is adapted from SharpUp (https://github.com/GhostPack/SharpUp)
*/
import System
import System.Management
import System.Security.AccessControl
import System.Security.Principal
import System.ServiceProcess
import System.Runtime.InteropServices
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


public static def GetModifiableServiceRegistry() as void:
    // checks if the current user has rights to modify the given registry

    scServices as (ServiceController) = ServiceController.GetServices();

    // rights that signify modifiable access
    // https://docs.microsoft.com/fr-fr/dotnet/api/system.security.accesscontrol.registryrights?view=netframework-4.8
    ModifyRights as List = [RegistryRights.ChangePermissions, RegistryRights.FullControl, RegistryRights.TakeOwnership, RegistryRights.SetValue, RegistryRights.WriteKey]

    print "\r\n=== Modifiable Registry Services  ===\r\n"

    identity as WindowsIdentity = WindowsIdentity.GetCurrent()

    for sc as ServiceController in scServices:
        try:
            key as RegistryKey = Registry.LocalMachine.OpenSubKey("SYSTEM\\\\CurrentControlSet\\\\Services\\\\" + sc.ServiceName)
            rules as AuthorizationRuleCollection = key.GetAccessControl().GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier))

            for rule as RegistryAccessRule in rules:
                if (identity.Groups.Contains(rule.IdentityReference) or rule.IdentityReference == identity.User):
                    for AccessRight as RegistryRights in ModifyRights:
                        if ((AccessRight & rule.RegistryRights) == AccessRight):
                            if (rule.AccessControlType == AccessControlType.Allow):
                                wmiData as ManagementObjectSearcher = ManagementObjectSearcher("root\\cimv2", String.Format("SELECT * FROM win32_service WHERE Name LIKE '{0}'", sc.ServiceName))
                                data as ManagementObjectCollection = wmiData.Get()

                                for result as ManagementObject in data:
                                    for i in ["Name", "DisplayName", "Description", "State", "StartMode", "PathName"]:
                                        if not result[i]:
                                            result[i] = ""
                                    print "  Name             : " + result["Name"]
                                    print "  DisplayName      : " + result["DisplayName"]
                                    print "  Description      : " + result["Description"]
                                    print "  RegistryKey      : SYSTEM\\\\CurrentControlSet\\\\Services\\\\" + sc.ServiceName
                                    print "  State            : " + result["State"]
                                    print "  StartMode        : " + result["StartMode"]
                                    print "  PathName         : " + result["PathName"] + "\r\n"
                                break
        except ex:
            print "  [X] Exception: " + ex


public static def Main():
    if IsHighIntegrity():
        print "[*] Already in high integrity, no need to privesc!"
    elif isAdmin():
        print "[*] In medium integrity but user is a local administrator - UAC can be bypassed."
    else:
        GetModifiableServiceRegistry()
