/*
    This module is inspired from SharpSploit (https://github.com/cobbr/SharpSploit)
*/
import System
import System.IO
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


private static def SetRegistryKeyValue(RegHiveKey as RegistryKey, RegValue as string, Value as string, ValueKind as RegistryValueKind) as bool:
    try:
        RegHiveKey.SetValue(RegValue, Value, ValueKind)
        return true
    except e:
        print e.GetType().FullName + ": " + e.Message
        return false


public def ArrayContains(arr as (string), st as string) as bool:
    for s in arr:
        if s.ToUpper() == st.ToUpper():
            return true
    return false


public static def SetRegistryKey(RegHive as RegistryHive, RegKey as string, RegValue as string, Value as string, ValueKind as RegistryValueKind) as bool:
    baseKey as RegistryKey = null
    if RegHive == RegistryHive.CurrentUser:
        baseKey = Registry.CurrentUser
    elif RegHive == RegistryHive.LocalMachine:
        baseKey = Registry.LocalMachine
    elif RegHive == RegistryHive.ClassesRoot:
        baseKey = Registry.ClassesRoot
    elif RegHive == RegistryHive.CurrentConfig:
        baseKey = Registry.CurrentConfig
    elif RegHive == RegistryHive.Users:
        baseKey = Registry.Users
    else:
        baseKey = Registry.CurrentUser
    pieces as (string) = RegKey.Split(Path.DirectorySeparatorChar)
    for i in range(0, pieces.Length):
        subkeynames as (string) = baseKey.GetSubKeyNames()
        if (not ArrayContains(subkeynames, pieces[i])):
            baseKey = baseKey.CreateSubKey(pieces[i])
        else:
            baseKey = baseKey.OpenSubKey(pieces[i], true)
    return SetRegistryKeyValue(baseKey, RegValue, Value, ValueKind)


public static def Main():
    RegHive = "REGISTRY_HIVE"
    RegKey = "REGISTRY_KEY"
    RegValue = "REGISTRY_VALUE"
    Value = "NEW_VALUE"
    ValueKind = "NEW_VAL_KIND"

    ValueType as RegistryValueKind
    if ValueKind == "Binary":
        ValueType = RegistryValueKind.Binary
    elif ValueKind == "DWord":
        ValueType = RegistryValueKind.DWord
    elif ValueKind == "ExpandString":
        ValueType = RegistryValueKind.ExpandString
    elif ValueKind == "MultiString":
        ValueType = RegistryValueKind.MultiString
    elif ValueKind == "None":
        ValueType = RegistryValueKind.None
    elif ValueKind == "QWord":
        ValueType = RegistryValueKind.QWord
    elif ValueKind == "String":
        ValueType = RegistryValueKind.String
    else:
        print "[X]: Unsupported ValueKind"
        return

    if SetRegistryKey(ConvertToRegistryHive(RegHive), RegKey, RegValue, Value, ValueType):
        print "Successfully wrote: \"" + Value + "\" to registry: " + RegHive + ":\\" + RegKey + "\\" + RegValue
    else:
        print "Failed to write: \"" + Value + "\" to registry: " + RegHive + ":\\" + RegKey + "\\" + RegValue
