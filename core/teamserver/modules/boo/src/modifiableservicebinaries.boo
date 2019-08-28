/*
    This module is adapted from SharpUp (https://github.com/GhostPack/SharpUp)
*/
import System
import System.IO
import System.Management
import System.Security.AccessControl
import System.Security.Principal
import System.Text.RegularExpressions

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


public static def CheckModifiableAccess(Path as string) as bool:
    // checks if the current user has rights to modify the given file/directory
    // adapted from https://stackoverflow.com/questions/1410127/c-sharp-test-if-user-has-write-access-to-a-folder/21996345#21996345

    if not Path:
        return false
    // TODO: check if file exists, check file's parent folder

    // rights that signify modiable access
    ModifyRights as List = [
        FileSystemRights.ChangePermissions,
        FileSystemRights.FullControl,
        FileSystemRights.Modify,
        FileSystemRights.TakeOwnership,
        FileSystemRights.Write,
        FileSystemRights.WriteData,
        FileSystemRights.CreateDirectories,
        FileSystemRights.CreateFiles
    ]

    paths as List = [Path]

    try:
        attr as FileAttributes = System.IO.File.GetAttributes(Path)
        if ((attr & FileAttributes.Directory) != FileAttributes.Directory):
            parentFolder as string = System.IO.Path.GetDirectoryName(Path)
            paths.Add(parentFolder)
    except a:
        return false

    try:
        for candidatePath as string in paths:
            rules as AuthorizationRuleCollection = Directory.GetAccessControl(candidatePath).GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier));
            identity as WindowsIdentity = WindowsIdentity.GetCurrent();

            for rule as FileSystemAccessRule in rules:
                if (identity.Groups.Contains(rule.IdentityReference)):
                    for AccessRight as FileSystemRights in ModifyRights:
                        if ((AccessRight & rule.FileSystemRights) == AccessRight):
                            if (rule.AccessControlType == AccessControlType.Allow):
                                return true
        return false
    except:
        return false


public static def GetModifiableServiceBinaries() as void:
    try:
        // finds any service binaries that the current can modify
        //      TODO: or modify the parent folder

        wmiData as ManagementObjectSearcher = ManagementObjectSearcher("root\\cimv2", "SELECT * FROM win32_service");
        data as ManagementObjectCollection = wmiData.Get();

        print "\r\n=== Modifiable Service Binaries ===\r\n"

        for result as ManagementObject in data:
            if result["PathName"]:
                path as Match = Regex.Match(result["PathName"].ToString(), "^\\W*([a-z]:\\\\.+?(\\.exe|\\.dll|\\.sys))\\W*", RegexOptions.IgnoreCase);
                binaryPath = path.Groups[1].ToString();

                if (CheckModifiableAccess(binaryPath)):
                    for i in ["Name", "DisplayName", "Description", "State", "StartMode", "PathName"]:
                        if not result[i]:
                            result[i] = ""
                    print "  Name             : " + result["Name"]
                    print "  DisplayName      : " + result["DisplayName"]
                    print "  Description      : " + result["Description"]
                    print "  State            : " + result["State"]
                    print "  StartMode        : " + result["StartMode"]
                    print "  PathName         : " + result["PathName"] + "\r\n"
    except ex:
        print "  [X] Exception: " + ex


public static def Main():
    if IsHighIntegrity():
        print "[*] Already in high integrity, no need to privesc!"
    elif isAdmin():
        print "[*] In medium integrity but user is a local administrator - UAC can be bypassed."
    else:
        GetModifiableServiceBinaries()
