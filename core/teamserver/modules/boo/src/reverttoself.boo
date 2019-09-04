/*
    This module is inspired from SharpSploit (https://github.com/cobbr/SharpSploit)
*/
import System
import System.ComponentModel
import System.Runtime.InteropServices
import System.Security.Principal

[DllImport("advapi32.dll", SetLastError: true)]
public static def RevertToSelf() as bool:
    pass


public static def Main():
    if (not RevertToSelf()):
        print "RevertToSelf() Error: " + Win32Exception(Marshal.GetLastWin32Error()).Message
    else:
        print "Successfully reverted to: " + WindowsIdentity.GetCurrent().Name
