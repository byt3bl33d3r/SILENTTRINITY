/*
    This module is inspired from SharpSploit (https://github.com/cobbr/SharpSploit)
*/
import System
import System.IO
import System.Security.Permissions
import Microsoft.Win32


public static def ConvertToRegistryHive(RegHive as string) as RegistryHive:
    if (RegHive == "HKEY_CURRENT_USER" or RegHive == "HKCU" or RegHive == "CURRENTUSER"):
        return RegistryHive.CurrentUser
    if (RegHive == "HKEY_LOCAL_MACHINE" or RegHive == "HKLM" or RegHive == "LOCALMACHINE"):
        return RegistryHive.LocalMachine
    if (RegHive == "HKEY_CLASSES_ROOT" or RegHive == "HKCR" or RegHive == "CLASSESROOT"):
        return RegistryHive.ClassesRoot
    if (RegHive == "HKEY_CURRENT_CONFIG" or RegHive == "HKCC" or RegHive == "CURRENTCONFIG"):
        return RegistryHive.CurrentConfig
    if (RegHive == "HKEY_USERS" or RegHive == "HKU"):
        return RegistryHive.Users
    return RegistryHive.CurrentUser


private static def GetRegistryKeyValue(RegHiveKey as RegistryKey, RegValue as string) as string:
    value as object = null
    try:
        value = RegHiveKey.GetValue(RegValue, null)
    except e:
        print "[X] Registry read exception: " + e.Message
    if value == null:
        return null
    return value.ToString()


public def ArrayContains(arr as (string), st as string) as bool:
    for s in arr:
        if s.ToUpper() == st.ToUpper():
            return true
    return false


public static def GetRemoteRegistryKey(Hostname as string, RegHive as RegistryHive, RegKey as string, RegValue as string) as string:
    baseKey as RegistryKey = null
    try:
      baseKey = RegistryKey.OpenRemoteBaseKey(RegHive, Hostname)
    except ex:
      print "[X] ERROR: " + ex.Message
      return

    pieces as (string) = RegKey.Split(Path.DirectorySeparatorChar)
    valuenames as (string)
    subkeynames as (string)
    output as string
    for i in range(0, pieces.Length):
        subkeynames = baseKey.GetSubKeyNames()
        valuenames = baseKey.GetValueNames()
        if (i == pieces.Length - 1 and ArrayContains(valuenames, pieces[i])):
            keyname as string = ""
            for j in range(0, pieces.Length - 1):
                keyname += pieces[j] + Path.DirectorySeparatorChar
            return GetRegistryKeyValue(baseKey, pieces[i])
        if (not ArrayContains(subkeynames, pieces[i])):
            return "\r\n[X] The specified Key does not exist."
        baseKey = baseKey.OpenSubKey(pieces[i])
    if (string.IsNullOrEmpty(RegValue)):
        subkeynames = baseKey.GetSubKeyNames()
        valuenames = baseKey.GetValueNames()
        output = Environment.NewLine + "Key: " + RegHive.ToString() + "\\" + RegKey + Environment.NewLine
        if (subkeynames != array(string, 0)):
            output += Environment.NewLine + "SubKeys:" + Environment.NewLine
            for subkeyname as string in subkeynames:
                output += "  " + subkeyname + Environment.NewLine
        if (valuenames != array(string, 0)):
            output += Environment.NewLine + "Values:"
            for valuename as string in valuenames:
                output += Environment.NewLine
                output += "  Name:  " + valuename + Environment.NewLine
                output += "  Kind:  " + baseKey.GetValueKind(valuename).ToString() + Environment.NewLine
                output += "  Value: " + baseKey.GetValue(valuename) + Environment.NewLine
        return output.Trim()
    output = "Key: " + RegHive.ToString() + "\\" + RegKey + Environment.NewLine
    output += Environment.NewLine
    output += "  Name:  " + RegValue + Environment.NewLine
    output += "  Kind:  " + baseKey.GetValueKind(RegValue).ToString() + Environment.NewLine
    output += "  Value: " + GetRegistryKeyValue(baseKey, RegValue) + Environment.NewLine
    return output.Trim()


public static def Main():
    HostName = "HOSTNAME"
    RegHive = "REGISTRY_HIVE"
    RegKey = "REGISTRY_KEY"
    RegValue = "REGISTRY_VALUE"

    print GetRemoteRegistryKey(HostName, ConvertToRegistryHive(RegHive), RegKey, RegValue)
