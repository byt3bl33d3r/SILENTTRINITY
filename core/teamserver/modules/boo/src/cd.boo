/*
    This module is inspired from SharpSploit (https://github.com/cobbr/SharpSploit)
*/
import System
import System.IO

public static def Main():
    path = `PATH`
    print "[*] Actual directory: " + Directory.GetCurrentDirectory() + "\r\n"
    print "[*] Going to directory: " + path + "\r\n"
    Directory.SetCurrentDirectory(path)
    print "[*] Now in: " + Directory.GetCurrentDirectory()
