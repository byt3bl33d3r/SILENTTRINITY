/*
    This module is adapted from SharpUp (https://github.com/GhostPack/SharpUp)
*/
import System
import System.Security.AccessControl
import System.Security.Principal


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


public static def GetUnattendedInstallFiles() as void:
    try:
        print "\r\n=== Unattended Install Files ===\r\n"

        windir as string = System.Environment.GetEnvironmentVariable("windir")
        SearchLocations as List = [
            String.Format("{0}\\sysprep\\sysprep.xml", windir),
            String.Format("{0}\\sysprep\\sysprep.inf", windir),
            String.Format("{0}\\sysprep.inf", windir),
            String.Format("{0}\\Panther\\Unattended.xml", windir),
            String.Format("{0}\\Panther\\Unattend.xml", windir),
            String.Format("{0}\\Panther\\Unattend\\Unattend.xml", windir),
            String.Format("{0}\\Panther\\Unattend\\Unattended.xml", windir),
            String.Format("{0}\\System32\\Sysprep\\unattend.xml", windir),
            String.Format("{0}\\System32\\Sysprep\\Panther\\unattend.xml", windir)
            ]

        for SearchLocation as string in SearchLocations:
            if (System.IO.File.Exists(SearchLocation)):
                print " " + SearchLocation
    except ex:
        print String.Format("  [X] Exception: {0}", ex.Message)


public static def Main():
    if IsHighIntegrity():
        print "[*] Already in high integrity, no need to privesc!"
    elif isAdmin():
        print "[*] In medium integrity but user is a local administrator - UAC can be bypassed."
    else:
        GetUnattendedInstallFiles()
