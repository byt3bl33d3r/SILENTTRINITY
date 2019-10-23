/*
    This module is adapted from SharpUp (https://github.com/GhostPack/SharpUp)
*/
import System
import System.Management
import System.Security.AccessControl
import System.Security.Claims
import System.Security.Principal
import System.ServiceProcess
import System.Reflection
import System.Runtime.InteropServices


enum ServiceAccessRights:
    QueryConfig = 0x00000001
    ChangeConfig = 0x00000002
    QueryStatus = 0x00000004
    EnumerateDependents = 0x00000008
    Start = 0x00000010
    Stop = 0x00000020
    PauseContinue = 0x00000040
    Interrogate = 0x00000080
    UserDefinedControl = 0x00000100
    Delete = 0x00010000
    ReadControl = 0x00020000
    WriteDac = 0x00040000
    WriteOwner = 0x00080000
    Synchronize = 0x00100000
    AccessSystemSecurity = 0x01000000
    GenericAll = 0x10000000
    GenericExecute = 0x20000000
    GenericWrite = 0x40000000
    GenericRead = 0x80000000
    AllAccess = 0x000F01FF

[DllImport("advapi32.dll")]
def QueryServiceObjectSecurity(serviceHandle as SafeHandle, secInfo as SecurityInfos, lpSecDesrBuf as (byte), bufSize as uint, ref bufSizeNeeded as uint) as bool:
    pass


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


public static def GetModifiableServices() as void:
    scServices as (ServiceController) = ServiceController.GetServices()
    readRights = array(object, (0x00020000))
    ModifyRights as (ServiceAccessRights) = (ServiceAccessRights.ChangeConfig,
      ServiceAccessRights.WriteDac,
      ServiceAccessRights.WriteOwner,
      ServiceAccessRights.GenericAll,
      ServiceAccessRights.GenericWrite,
      ServiceAccessRights.AllAccess)

    print "\r\n=== Modifiable Services ===\r\n"

    for sc in scServices:
        try:
            handle = sc.ServiceHandle
            status = sc.Status
            psd as (byte)
            bufSizeNeeded as uint
            ok = QueryServiceObjectSecurity(handle, SecurityInfos.DiscretionaryAcl, psd, 0, bufSizeNeeded)
            if not ok:
                err = Marshal.GetLastWin32Error()
                if (err == 122 or err == 0):
                    psd = array(byte, bufSizeNeeded cast uint)
                    ok = QueryServiceObjectSecurity(handle, SecurityInfos.DiscretionaryAcl, psd, bufSizeNeeded cast uint, bufSizeNeeded)
                else:
                    continue
            if not ok:
                continue

            rsd as RawSecurityDescriptor = RawSecurityDescriptor(psd, 0)
            racl as RawAcl = rsd.DiscretionaryAcl
            dacl as DiscretionaryAcl = DiscretionaryAcl(false, false, racl)
            identity as WindowsIdentity = WindowsIdentity.GetCurrent()

            for ace as CommonAce in dacl:
                if (identity.Groups.Contains(ace.SecurityIdentifier) or ace.SecurityIdentifier == identity.User):
                    serviceRights as ServiceAccessRights = ace.AccessMask
                    for ModifyRight in ModifyRights:
                        if ((ModifyRight & serviceRights) cast ServiceAccessRights == ModifyRight):
                            query = "SELECT * FROM win32_service WHERE Name LIKE '" + sc.ServiceName + "'"
                            wmiData as ManagementObjectSearcher = ManagementObjectSearcher("root\\cimv2", query)
                            data as ManagementObjectCollection = wmiData.Get()

                            for result as ManagementObject in data:
                                for i in ["Name", "DisplayName", "Description", "State", "StartMode", "PathName"]:
                                    if not result[i]:
                                        result[i] = ""
                                print "  Name             : " + result["Name"]
                                print "  DisplayName      : " + result["DisplayName"]
                                print "  Description      : " + result["Description"]
                                print "  State            : " + result["State"]
                                print "  StartMode        : " + result["StartMode"]
                                print "  PathName         : " + result["PathName"] + "\r\n"
                            break
        except ex:
            pass


public static def Main():
    if IsHighIntegrity():
        print "[*] Already in high integrity, no need to privesc!"
    elif isAdmin():
        print "[*] In medium integrity but user is a local administrator - UAC can be bypassed."
    else:
        GetModifiableServices()
