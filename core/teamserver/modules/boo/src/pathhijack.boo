/*
    This module is adapted from SharpUp (https://github.com/GhostPack/SharpUp)
*/
import System
import System.IO
import System.Security.AccessControl
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


public static def GetRegValue( path as string, value as string) as string:
    // returns a single registry value under the specified path in the HKLM hive
    regKeyValue as string
    regKey = Registry.LocalMachine.OpenSubKey(path)
    if regKey:
        regKeyValue = String.Format("{0}", regKey.GetValue(value))
    return regKeyValue


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


public static def GetPathHijacks() as void:
    print "\r\n=== Modifiable Folders in %PATH% ===\r\n"

    // grabbed from the registry instead of System.Environment.GetEnvironmentVariable to prevent false positives
    path as string = GetRegValue("SYSTEM\\\\CurrentControlSet\\\\Control\\\\Session Manager\\\\Environment", "Path")
    //pathFolders = path.Split(';')
    pathFolders = @/;/.Split(path)

    for pathFolder as string in pathFolders:
        if CheckModifiableAccess(pathFolder):
            print "  Modifable %PATH% Folder  : " + pathFolder


public static def Main():
    if IsHighIntegrity():
        print "[*] Already in high integrity, no need to privesc!"
    elif isAdmin():
        print "[*] In medium integrity but user is a local administrator - UAC can be bypassed."
    else:
        GetPathHijacks()
