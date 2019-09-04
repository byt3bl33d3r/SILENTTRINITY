/*
    This module is inspired from SharpSploit (https://github.com/cobbr/SharpSploit)
*/
import System
import System.Security.Principal

public static def Main():
    print WindowsIdentity.GetCurrent().Name
