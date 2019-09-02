/*
    This module is adapted from SharpUp (https://github.com/GhostPack/SharpUp)
*/
import System
import System.IO
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


public static def FindFiles(path as string, patterns as string) as List:
    // finds files matching one or more patterns under a given path, recursive
    // adapted from http://csharphelper.com/blog/2015/06/find-files-that-match-multiple-patterns-in-c/
    //      pattern: "*pass*;*.png;"

    files as List
    try:
        // search every pattern in this directory's files
        for pattern as string in (@/;/.Split(patterns)):
            for f as string in Directory.GetFiles(path, pattern, SearchOption.TopDirectoryOnly):
                if f:
                    files.Add(f)

        // go recurse in all sub-directories
        for directory in Directory.GetDirectories(path):
            if directory:
                newfiles as List = FindFiles(directory, patterns)
                if newfiles:
                    files += newfiles
    except e as UnauthorizedAccessException:
        pass
    except e as PathTooLongException:
        pass

    return files


public static def GetMcAfeeSitelistFiles() as void:
    try:
        print "\r\n=== McAfee Sitelist.xml Files ===\r\n"

        drive as string = System.Environment.GetEnvironmentVariable("SystemDrive")

        SearchLocations as List = [
            String.Format("{0}\\Program Files\\", drive),
            String.Format("{0}\\Program Files (x86)\\", drive),
            String.Format("{0}\\Documents and Settings\\", drive),
            String.Format("{0}\\Users\\", drive)
        ]

        for SearchLocation as string in SearchLocations:
            files as List = FindFiles(SearchLocation, "SiteList.xml")
            if files:
                for file as string in files:
                    if file:
                        print " " + file
    except ex:
        print String.Format("  [X] Exception: {0}", ex)


public static def Main():
    if IsHighIntegrity():
        print "[*] Already in high integrity, no need to privesc!"
    elif isAdmin():
        print "[*] In medium integrity but user is a local administrator - UAC can be bypassed."
    else:
        GetMcAfeeSitelistFiles()
