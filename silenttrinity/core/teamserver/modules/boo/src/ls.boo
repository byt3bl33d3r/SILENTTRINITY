/*
    This module is inspired from SharpSploit (https://github.com/cobbr/SharpSploit)
*/
import System
import System.IO

public static def Main():
    path = `PATH`
    if not path:
        path = Directory.GetCurrentDirectory()
    print "[*] Listing content of directory: " + path + "\r\n"
    print "Directories:"
    for dir as string in Directory.GetDirectories(path):
        print "     " + dir

    print "\r\nFiles:"
    for file as string in Directory.GetFiles(path):
        print "     " + file
