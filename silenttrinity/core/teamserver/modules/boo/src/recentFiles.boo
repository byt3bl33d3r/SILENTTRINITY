/*

Stolen from SeatBelt (https://github.com/GhostPack/Seatbelt/)

*/

import System
import System.IO
import System.Reflection
import System.Security.Principal
import System.Runtime.InteropServices

public static def IsHighIntegrity() as bool:
    identity = WindowsIdentity.GetCurrent()
    principal = WindowsPrincipal(identity)
    return principal.IsInRole(WindowsBuiltInRole.Administrator)

public static def ListRecentFiles(lastDays as int):
    // parses recent file shortcuts via COM

    startTime as DateTime = DateTime.Now.AddDays(-lastDays)
    recenpath as string
    recentFiles as (string)
    lastAccessed as DateTime
    shortcut as object
    TargetPath as object

    try:
        // WshShell COM object GUID
        shell as Type = Type.GetTypeFromCLSID(Guid("F935DC22-1CF0-11d0-ADB9-00C04FD58A0B"))
        shellObj as object = Activator.CreateInstance(shell)

        if IsHighIntegrity():
            print "=== Recently Accessed Files (All Users) Last $(lastDays) Days ===\r\n"

            userFolder as string = String.Format("{0}\\Users\\", Environment.GetEnvironmentVariable("SystemDrive"))
            dirs as (string) = Directory.GetDirectories(userFolder)
            for dir in dirs:
                parts as (string) = @/\\/.Split(dir)
                userName as string = parts[parts.Length - 1]
                if not (dir.EndsWith("Public") or dir.EndsWith("Default") or dir.EndsWith("Default User") or dir.EndsWith("All Users")):
                    recentPath = String.Format("{0}\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\", dir)
                    try:
                        recentFiles = Directory.GetFiles(recentPath, "*.lnk", SearchOption.AllDirectories)
                        if recentFiles.Length != 0:
                            print "   $(userName) :\r\n"
                            for recentFile in recentFiles:
                                lastAccessed = File.GetLastAccessTime(recentFile)

                                if lastAccessed > startTime:
                                    // invoke the WshShell com object, creating a shortcut to then extract the TargetPath from
                                    shortcut = shellObj.GetType().InvokeMember("CreateShortcut", BindingFlags.InvokeMethod, null, shellObj, (recentFile,))
                                    TargetPath = shortcut.GetType().InvokeMember("TargetPath", BindingFlags.GetProperty, null, shortcut, (,))

                                    if TargetPath.ToString().Trim() != "":
                                        print "      Target: $(TargetPath.ToString)"
                                        print "          Accessed: $(lastAccessed)\r\n"

                                    Marshal.ReleaseComObject(shortcut)
                                    shortcut = null
                    except e as Exception:
                        pass
        else:
            print "=== Recently Accessed Files (Current User) Last $(lastDays) Days ===\r\n"

            recentPath = "$(Environment.GetEnvironmentVariable('APPDATA'))\\Microsoft\\Windows\\Recent\\"

            recentFiles = Directory.GetFiles(recentPath, "*.lnk", SearchOption.AllDirectories)

            for recentFile in recentFiles:
                // old method (needed interop dll)
                //WshShell shell = new WshShell();
                //IWshShortcut shortcut = (IWshShortcut)shell.CreateShortcut(recentFile);

                lastAccessed = File.GetLastAccessTime(recentFile)
                if lastAccessed > startTime:
                    // invoke the WshShell com object, creating a shortcut to then extract the TargetPath from
                    shortcut = shellObj.GetType().InvokeMember("CreateShortcut", BindingFlags.InvokeMethod, null, shellObj, (recentFile,))
                    TargetPath = shortcut.GetType().InvokeMember("TargetPath", BindingFlags.GetProperty, null, shortcut, (,))
                    if TargetPath.ToString().Trim() != "":
                        print "    Target: $(TargetPath.ToString())"
                        print "        Accessed: $(lastAccessed)\r\n"

                    Marshal.ReleaseComObject(shortcut)
                    shortcut = null

        // release the WshShell COM object
        Marshal.ReleaseComObject(shellObj)
        shellObj = null
    except ex as Exception:
        print "  [X] Exception: $(ex.Message)"

public static def Main():
    ListRecentFiles(LAST_DAYS)
