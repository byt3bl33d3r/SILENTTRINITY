/*
    This module is adapted from SharpUp (https://github.com/GhostPack/SharpUp)
*/
import System
import System.IO
import System.Security.AccessControl
import System.Security.Principal
import System.Text.RegularExpressions
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


public static def GetRegValue(path as string, value as string) as string:
    // returns a single registry value under the specified path in the HKLM hive
    regKeyValue as string
    regKey = Registry.LocalMachine.OpenSubKey(path)
    if regKey:
        regKeyValue = String.Format("{0}", regKey.GetValue(value))
    return regKeyValue


public static def GetModifiableRegistryAutoRuns() as void:
    print "\r\n=== Modifiable Registry Autoruns ===\r\n"

    autorunLocations as List = [
        "SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run",
        "SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce",
        "SOFTWARE\\\\Wow6432Node\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run",
        "SOFTWARE\\\\Wow6432Node\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce",
        "SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunService",
        "SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnceService",
        "SOFTWARE\\\\Wow6432Node\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunService",
        "SOFTWARE\\\\Wow6432Node\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnceService"
    ]

    for autorunLocation as string in autorunLocations:
        regKeyValues as RegistryKey = Registry.LocalMachine.OpenSubKey(autorunLocation)
        if regKeyValues:
            valueNames = regKeyValues.GetValueNames()

            for v in valueNames:
                path as Match = Regex.Match(GetRegValue(autorunLocation, v), "^\\W*([a-z]:\\\\.+?(\\.exe|\\.bat|\\.ps1|\\.vbs))\\W*", RegexOptions.IgnoreCase)
                binaryPath as string = path.Groups[1].ToString()

                if (CheckModifiableAccess(binaryPath)):
                    print String.Format("  HKLM:\\\\{0} : {1}", autorunLocation, binaryPath)


public static def Main():
    if IsHighIntegrity():
        print "[*] Already in high integrity, no need to privesc!"
    elif isAdmin():
        print "[*] In medium integrity but user is a local administrator - UAC can be bypassed."
    else:
        GetModifiableRegistryAutoRuns()
