/*
    This module is adapted from SharpUp (https://github.com/GhostPack/SharpUp)
*/
import System
import System.Security.AccessControl
import System.Security.Principal
import System.Runtime.InteropServices


enum TOKEN_INFORMATION_CLASS:
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

enum LuidAttributes:
    DISABLED = 0x00000000
    SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001
    SE_PRIVILEGE_ENABLED = 0x00000002
    SE_PRIVILEGE_REMOVED = 0x00000004
    SE_PRIVILEGE_USED_FOR_ACCESS = 0x80000000

struct LUID:
    LowPart as uint
    HighPart as int

struct LUID_AND_ATTRIBUTES:
    Luid as LUID
    Attributes as LuidAttributes

struct TOKEN_PRIVILEGES:
    PrivilegeCount as int
    Privileges as (LUID_AND_ATTRIBUTES)

[DllImport("advapi32.dll")]
def GetTokenInformation(TokenHandle as IntPtr, TokenInformationClass as TOKEN_INFORMATION_CLASS, TokenInformation as IntPtr, TokenInformationLength as int, ref ReturnLength as int) as bool:
    pass

[DllImport("advapi32.dll")]
def LookupPrivilegeName(lpSystemName as string, lpLuid as IntPtr, lpName as System.Text.StringBuilder, cchName as int) as bool:
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


public static def GetSpecialTokenGroupPrivs() as void:
    // Returns all "special" privileges that the current process/user possesses
    // adapted from https://stackoverflow.com/questions/4349743/setting-size-of-token-privileges-luid-and-attributes-array-returned-by-gettokeni

    print "\r\n=== *Special* User Privileges ===\r\n"

    SpecialPrivileges as List = [
        "SeSecurityPrivilege",
        "SeTakeOwnershipPrivilege",
        "SeLoadDriverPrivilege",
        "SeBackupPrivilege",
        "SeRestorePrivilege",
        "SeDebugPrivilege",
        "SeSystemEnvironmentPrivilege",
        "SeImpersonatePrivilege",
        "SeTcbPrivilege"
    ]

    TokenInfLength as int = 0
    ThisHandle as IntPtr = WindowsIdentity.GetCurrent().Token
    GetTokenInformation(ThisHandle, TOKEN_INFORMATION_CLASS.TokenPrivileges, IntPtr.Zero, TokenInfLength, TokenInfLength)
    TokenInformation as IntPtr
    if (GetTokenInformation(WindowsIdentity.GetCurrent().Token, TOKEN_INFORMATION_CLASS.TokenPrivileges, TokenInformation, TokenInfLength, TokenInfLength)):
        ThisPrivilegeSet as TOKEN_PRIVILEGES = Marshal.PtrToStructure(TokenInformation, typeof(TOKEN_PRIVILEGES))
        for index in range(0, ThisPrivilegeSet.PrivilegeCount):
            laa as LUID_AND_ATTRIBUTES = ThisPrivilegeSet.Privileges[index]
            StrBuilder as System.Text.StringBuilder
            LuidNameLen as int = 0
            LuidPointer as IntPtr
            Marshal.StructureToPtr(laa.Luid, LuidPointer, true)
            LookupPrivilegeName(null, LuidPointer, null, LuidNameLen)
            StrBuilder.EnsureCapacity(LuidNameLen + 1)
            if (LookupPrivilegeName(null, LuidPointer, StrBuilder, LuidNameLen)):
                privilege as string = StrBuilder.ToString()
                for SpecialPrivilege as string in SpecialPrivileges:
                    if (privilege == SpecialPrivilege):
                        print String.Format("  {0,43}:  {1}", privilege, laa.Attributes cast LuidAttributes)


public static def Main():
    if IsHighIntegrity():
        print "[*] Already in high integrity, no need to privesc!"
    elif isAdmin():
        print "[*] In medium integrity but user is a local administrator - UAC can be bypassed."
    else:
        GetSpecialTokenGroupPrivs()
