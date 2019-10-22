/*
    This module is inspired from SharpSploit (https://github.com/cobbr/SharpSploit)
*/
import System
import System.ComponentModel
import System.Runtime.InteropServices
import System.Security.Principal

public enum LOGON_TYPE:
    LOGON32_LOGON_INTERACTIVE = 2
    LOGON32_LOGON_NETWORK
    LOGON32_LOGON_BATCH
    LOGON32_LOGON_SERVICE
    LOGON32_LOGON_UNLOCK = 7
    LOGON32_LOGON_NETWORK_CLEARTEXT
    LOGON32_LOGON_NEW_CREDENTIALS


public enum LOGON_PROVIDER:
    LOGON32_PROVIDER_DEFAULT
    LOGON32_PROVIDER_WINNT35
    LOGON32_PROVIDER_WINNT40
    LOGON32_PROVIDER_WINNT50


[DllImport("advapi32.dll", SetLastError: true)]
public static def LogonUserA(
    lpszUsername as string,
    lpszDomain as string,
    lpszPassword as string,
    dwLogonType as LOGON_TYPE,
    dwLogonProvider as LOGON_PROVIDER,
    ref phToken as IntPtr
) as bool:
    pass


[DllImport("advapi32.dll", SetLastError: true)]
public static def ImpersonateLoggedOnUser(
    hToken as IntPtr
) as bool:
    pass


public def MakeToken(Username as string, Domain as string, Password as string, LogonType as LOGON_TYPE) as bool:
    hProcessToken as IntPtr = IntPtr.Zero
    if (not LogonUserA(
        Username, Domain, Password,
        LogonType, LOGON_PROVIDER.LOGON32_PROVIDER_DEFAULT,
        hProcessToken)
        ):
        print "LogonUserA() Error: " + Win32Exception(Marshal.GetLastWin32Error()).Message
        return false

    if (not ImpersonateLoggedOnUser(hProcessToken)):
        print "ImpersonateLoggedOnUser() Error: " + Win32Exception(Marshal.GetLastWin32Error()).Message
        return false
    return true


public static def Main():
    Username = "USERNAME"
    Domain = "DOMAIN"
    Password = "PASSWORD"
    LogonType = "LOGON_TYPE"

    lt as LOGON_TYPE = LOGON_TYPE.LOGON32_LOGON_NEW_CREDENTIALS
    if (LogonType == "LOGON32_LOGON_INTERACTIVE"):
        lt = LOGON_TYPE.LOGON32_LOGON_INTERACTIVE
    elif (LogonType == "LOGON32_LOGON_NETWORK"):
        lt = LOGON_TYPE.LOGON32_LOGON_NETWORK
    elif (LogonType == "LOGON32_LOGON_BATCH"):
        lt = LOGON_TYPE.LOGON32_LOGON_BATCH
    elif (LogonType == "LOGON32_LOGON_SERVICE"):
        lt = LOGON_TYPE.LOGON32_LOGON_SERVICE
    elif (LogonType == "LOGON32_LOGON_UNLOCK"):
        lt = LOGON_TYPE.LOGON32_LOGON_UNLOCK
    elif (LogonType == "LOGON32_LOGON_NETWORK_CLEARTEXT"):
        lt = LOGON_TYPE.LOGON32_LOGON_NETWORK_CLEARTEXT
    elif (LogonType != "LOGON32_LOGON_NEW_CREDENTIALS"):
        print "MakeToken failed. Invalid LogonType specified."

    if (MakeToken(Username, Domain, Password, lt)):
        print "Successfully made and impersonated token for user: " + Domain + "\\" + Username
    else:
        print "Failed to make token for user: " + Domain + "\\" + Username

    // Eventually add code there to execute command
