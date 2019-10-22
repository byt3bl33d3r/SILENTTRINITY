/* 

This is a complete port of @Harmjoy's Seatbelt tool to Boolang

All credit goes to him for writing this beast 

https://github.com/GhostPack/Seatbelt

*/

import System
import System.Collections
import System.Collections.Generic
import System.Diagnostics
import System.Diagnostics.Eventing.Reader
import System.IO
import System.Linq
import System.Management
import System.Net
import System.Net.NetworkInformation
import System.Reflection
import System.Runtime.InteropServices
import System.Security.AccessControl
import System.Security.Principal
import System.Text
import System.Text.RegularExpressions
import System.Web.Script.Serialization
import Microsoft.Win32
import System.Xml


public enum KERB_PROTOCOL_MESSAGE_TYPE:
    KerbDebugRequestMessage = 0
    KerbQueryTicketCacheMessage = 1
    KerbChangeMachinePasswordMessage = 2
    KerbVerifyPacMessage = 3
    KerbRetrieveTicketMessage = 4
    KerbUpdateAddressesMessage = 5
    KerbPurgeTicketCacheMessage = 6
    KerbChangePasswordMessage = 7
    KerbRetrieveEncodedTicketMessage = 8
    KerbDecryptDataMessage = 9
    KerbAddBindingCacheEntryMessage = 10
    KerbSetPasswordMessage = 11
    KerbSetPasswordExMessage = 12
    KerbVerifyCredentialsMessage = 13
    KerbQueryTicketCacheExMessage = 14
    KerbPurgeTicketCacheExMessage = 15
    KerbRefreshSmartcardCredentialsMessage = 16
    KerbAddExtraCredentialsMessage = 17
    KerbQuerySupplementalCredentialsMessage = 18
    KerbTransferCredentialsMessage = 19
    KerbQueryTicketCacheEx2Message = 20
    KerbSubmitTicketMessage = 21
    KerbAddExtraCredentialsExMessage = 22
    KerbQueryKdcProxyCacheMessage = 23
    KerbPurgeKdcProxyCacheMessage = 24
    KerbQueryTicketCacheEx3Message = 25
    KerbCleanupMachinePkinitCredsMessage = 26
    KerbAddBindingCacheEntryExMessage = 27
    KerbQueryBindingCacheMessage = 28
    KerbPurgeBindingCacheMessage = 29
    KerbQueryDomainExtendedPoliciesMessage = 30
    KerbQueryS4U2ProxyCacheMessage = 31

public enum KERB_ENCRYPTION_TYPE:
    reserved0 = 0
    des_cbc_crc = 1
    des_cbc_md4 = 2
    des_cbc_md5 = 3
    reserved1 = 4
    des3_cbc_md5 = 5
    reserved2 = 6
    des3_cbc_sha1 = 7
    dsaWithSHA1_CmsOID = 9
    md5WithRSAEncryption_CmsOID = 10
    sha1WithRSAEncryption_CmsOID = 11
    rc2CBC_EnvOID = 12
    rsaEncryption_EnvOID = 13
    rsaES_OAEP_ENV_OID = 14
    des_ede3_cbc_Env_OID = 15
    des3_cbc_sha1_kd = 16
    aes128_cts_hmac_sha1_96 = 17
    aes256_cts_hmac_sha1_96 = 18
    aes128_cts_hmac_sha256_128 = 19
    aes256_cts_hmac_sha384_192 = 20
    rc4_hmac = 23
    rc4_hmac_exp = 24
    camellia128_cts_cmac = 25
    camellia256_cts_cmac = 26
    subkey_keymaterial = 65

[Flags]
private enum KERB_CACHE_OPTIONS:
    KERB_RETRIEVE_TICKET_DEFAULT = 0x0
    KERB_RETRIEVE_TICKET_DONT_USE_CACHE = 0x1
    KERB_RETRIEVE_TICKET_USE_CACHE_ONLY = 0x2
    KERB_RETRIEVE_TICKET_USE_CREDHANDLE = 0x4
    KERB_RETRIEVE_TICKET_AS_KERB_CRED = 0x8
    KERB_RETRIEVE_TICKET_WITH_SEC_CRED = 0x10
    KERB_RETRIEVE_TICKET_CACHE_TICKET = 0x20
    KERB_RETRIEVE_TICKET_MAX_LIFETIME = 0x40

// TODO: double check these flags...
// https://docs.microsoft.com/en-us/windows/desktop/api/ntsecapi/ns-ntsecapi-_kerb_external_ticket
[Flags]
public enum KERB_TICKET_FLAGS:
    reserved = 2147483648
    forwardable = 0x40000000
    forwarded = 0x20000000
    proxiable = 0x10000000
    proxy = 0x08000000
    may_postdate = 0x04000000
    postdated = 0x02000000
    invalid = 0x01000000
    renewable = 0x00800000
    initial = 0x00400000
    pre_authent = 0x00200000
    hw_authent = 0x00100000
    ok_as_delegate = 0x00040000
    name_canonicalize = 0x00010000
    //cname_in_pa_data = 0x00040000
    enc_pa_rep = 0x00010000
    reserved1 = 0x00000001


// used to fignal whether filtering should be done on results
public static class FilterResults:

    public static filter = true


public static class NetworkAPI:

    // from boboes' code at https://stackoverflow.com/questions/33935825/pinvoke-netlocalgroupgetmembers-runs-into-fatalexecutionengineerror/33939889#33939889

    [DllImport('Netapi32.dll')]
    public static def NetLocalGroupGetMembers([MarshalAs(UnmanagedType.LPWStr)] servername as string, [MarshalAs(UnmanagedType.LPWStr)] localgroupname as string, level as int, ref bufptr as IntPtr, prefmaxlen as int, ref entriesread as int, ref totalentries as int, ref resumehandle as IntPtr) as uint:
        pass


    [DllImport('Netapi32.dll')]
    public static def NetApiBufferFree(Buffer as IntPtr) as int:
        pass


    // LOCALGROUP_MEMBERS_INFO_2 - Structure for holding members details
    [StructLayout(LayoutKind.Sequential, CharSet: CharSet.Unicode)]
    public struct LOCALGROUP_MEMBERS_INFO_2:

        public lgrmi2_sid as IntPtr

        public lgrmi2_sidusage as int

        public lgrmi2_domainandname as string


    // documented in MSDN
    public static final ERROR_ACCESS_DENIED as uint = 5

    public static final ERROR_MORE_DATA as uint = 234

    public static final ERROR_NO_SUCH_ALIAS as uint = 1376

    public static final NERR_InvalidComputer as uint = 2351


    // found by testing
    public static final NERR_GroupNotFound as uint = 2220

    public static final SERVER_UNAVAILABLE as uint = 1722


public static class VaultCli:

    // pulled directly from @djhohnstein's SharpWeb project: https://github.com/djhohnstein/SharpWeb/blob/master/Edge/SharpEdge.cs
    public enum VAULT_ELEMENT_TYPE:
        Undefined = -1
        Boolean = 0
        Short = 1
        UnsignedShort = 2
        Int = 3
        UnsignedInt = 4
        Double = 5
        Guid = 6
        String = 7
        ByteArray = 8
        TimeStamp = 9
        ProtectedArray = 10
        Attribute = 11
        Sid = 12
        Last = 13

    public enum VAULT_SCHEMA_ELEMENT_ID:
        Illegal = 0
        Resource = 1
        Identity = 2
        Authenticator = 3
        Tag = 4
        PackageSid = 5
        AppStart = 100
        AppEnd = 10000

    [StructLayout(LayoutKind.Sequential, CharSet: CharSet.Ansi)]
    public struct VAULT_ITEM_WIN8:

        public SchemaId as Guid

        public pszCredentialFriendlyName as IntPtr

        public pResourceElement as IntPtr

        public pIdentityElement as IntPtr

        public pAuthenticatorElement as IntPtr

        public pPackageSid as IntPtr

        public LastModified as UInt64

        public dwFlags as UInt32

        public dwPropertiesCount as UInt32

        public pPropertyElements as IntPtr


    [StructLayout(LayoutKind.Sequential, CharSet: CharSet.Ansi)]
    public struct VAULT_ITEM_WIN7:

        public SchemaId as Guid

        public pszCredentialFriendlyName as IntPtr

        public pResourceElement as IntPtr

        public pIdentityElement as IntPtr

        public pAuthenticatorElement as IntPtr

        public LastModified as UInt64

        public dwFlags as UInt32

        public dwPropertiesCount as UInt32

        public pPropertyElements as IntPtr


    [StructLayout(LayoutKind.Explicit, CharSet: CharSet.Ansi)]
    public struct VAULT_ITEM_ELEMENT:

        [FieldOffset(0)]
        public SchemaElementId as VAULT_SCHEMA_ELEMENT_ID

        [FieldOffset(8)]
        public Type as VAULT_ELEMENT_TYPE


    [DllImport('vaultcli.dll')]
    public static def VaultOpenVault(ref vaultGuid as Guid, offset as UInt32, ref vaultHandle as IntPtr) as Int32:
        pass


    [DllImport('vaultcli.dll')]
    public static def VaultCloseVault(ref vaultHandle as IntPtr) as Int32:
        pass


    [DllImport('vaultcli.dll')]
    public static def VaultFree(ref vaultHandle as IntPtr) as Int32:
        pass


    [DllImport('vaultcli.dll')]
    public static def VaultEnumerateVaults(offset as Int32, ref vaultCount as Int32, ref vaultGuid as IntPtr) as Int32:
        pass


    [DllImport('vaultcli.dll')]
    public static def VaultEnumerateItems(vaultHandle as IntPtr, chunkSize as Int32, ref vaultItemCount as Int32, ref vaultItem as IntPtr) as Int32:
        pass


    [DllImport('vaultcli.dll', EntryPoint: 'VaultGetItem')]
    public static def VaultGetItem_WIN8(vaultHandle as IntPtr, ref schemaId as Guid, pResourceElement as IntPtr, pIdentityElement as IntPtr, pPackageSid as IntPtr, zero as IntPtr, arg6 as Int32, ref passwordVaultPtr as IntPtr) as Int32:
        pass


    [DllImport('vaultcli.dll', EntryPoint: 'VaultGetItem')]
    public static def VaultGetItem_WIN7(vaultHandle as IntPtr, ref schemaId as Guid, pResourceElement as IntPtr, pIdentityElement as IntPtr, zero as IntPtr, arg5 as Int32, ref passwordVaultPtr as IntPtr) as Int32:
        pass




public class SeatBelt:

    // PInvoke signature definitions
    [DllImport("mpr.dll", CharSet: CharSet.Unicode, SetLastError: true)]
    public static def WNetGetConnection([MarshalAs(UnmanagedType.LPTStr)] localName as string, [MarshalAs(UnmanagedType.LPTStr)] remoteName as StringBuilder, ref length as int) as int:
        pass

    [DllImport('advapi32', CharSet: CharSet.Auto, SetLastError: true)]
    private static def ConvertSidToStringSid(pSID as IntPtr, ref ptrSid as IntPtr) as bool:
        pass


    [DllImport('kernel32.dll')]
    private static def LocalFree(hMem as IntPtr) as IntPtr:
        pass


    [DllImport('advapi32.dll', SetLastError: true)]
    private static def GetTokenInformation(TokenHandle as IntPtr, TokenInformationClass as TOKEN_INFORMATION_CLASS, TokenInformation as IntPtr, TokenInformationLength as int, ref ReturnLength as int) as bool:
        pass


    [DllImport('advapi32.dll', SetLastError: true, CharSet: CharSet.Auto)]
    protected static def LookupPrivilegeName(lpSystemName as string, lpLuid as IntPtr, lpName as System.Text.StringBuilder, ref cchName as int) as bool:
        pass


    [DllImport('wtsapi32.dll', SetLastError: true)]
    private static def WTSOpenServer([MarshalAs(UnmanagedType.LPStr)] pServerName as String) as IntPtr:
        pass


    [DllImport('wtsapi32.dll')]
    private static def WTSCloseServer(hServer as IntPtr):
        pass


    [DllImport('wtsapi32.dll', SetLastError: true)]
    private static def WTSEnumerateSessions(hServer as IntPtr, [MarshalAs(UnmanagedType.U4)] Reserved as Int32, [MarshalAs(UnmanagedType.U4)] Version as Int32, ref ppSessionInfo as IntPtr, [MarshalAs(UnmanagedType.U4)] ref pCount as Int32) as Int32:
        pass


    [DllImport('wtsapi32.dll', SetLastError: true)]
    private static def WTSEnumerateSessionsEx(hServer as IntPtr, [MarshalAs(UnmanagedType.U4)] ref pLevel as Int32, [MarshalAs(UnmanagedType.U4)] Filter as Int32, ref ppSessionInfo as IntPtr, [MarshalAs(UnmanagedType.U4)] ref pCount as Int32) as Int32:
        pass


    [DllImport('wtsapi32.dll')]
    private static def WTSFreeMemory(pMemory as IntPtr):
        pass


    [DllImport('Wtsapi32.dll', SetLastError: true)]
    private static def WTSQuerySessionInformation(hServer as IntPtr, sessionId as uint, wtsInfoClass as WTS_INFO_CLASS, ref ppBuffer as IntPtr, ref pBytesReturned as uint) as bool:
        pass


    [DllImport('iphlpapi.dll', SetLastError: true)]
    public static def GetExtendedTcpTable(pTcpTable as IntPtr, ref dwOutBufLen as uint, sort as bool, ipVersion as int, tblClass as TCP_TABLE_CLASS, reserved as int) as uint:
        pass


    [DllImport('advapi32.dll', SetLastError: true)]
    public static def I_QueryTagInformation(Unknown as IntPtr, Type as SC_SERVICE_TAG_QUERY_TYPE, ref Query as SC_SERVICE_TAG_QUERY) as uint:
        pass


    [DllImport('iphlpapi.dll', SetLastError: true)]
    public static def GetExtendedUdpTable(pUdpTable as IntPtr, ref dwOutBufLen as uint, sort as bool, ipVersion as int, tblClass as UDP_TABLE_CLASS, reserved as int) as uint:
        pass


    [DllImport('secur32.dll', SetLastError: false)]
    private static def LsaConnectUntrusted([Out] ref LsaHandle as IntPtr) as int:
        pass


    [DllImport('secur32.dll', SetLastError: true)]
    public static def LsaRegisterLogonProcess(LogonProcessName as LSA_STRING_IN, ref LsaHandle as IntPtr, ref SecurityMode as ulong) as int:
        pass


    [DllImport('secur32.dll', SetLastError: false)]
    private static def LsaDeregisterLogonProcess([In] LsaHandle as IntPtr) as int:
        pass


    [DllImport('secur32.dll', SetLastError: false)]
    public static def LsaLookupAuthenticationPackage([In] LsaHandle as IntPtr, [In] ref PackageName as LSA_STRING_IN, [Out] ref AuthenticationPackage as int) as int:
        pass


    [DllImport('secur32.dll', SetLastError: false)]
    private static def LsaCallAuthenticationPackage(LsaHandle as IntPtr, AuthenticationPackage as int, ref ProtocolSubmitBuffer as KERB_QUERY_TKT_CACHE_REQUEST, SubmitBufferLength as int, ref ProtocolReturnBuffer as IntPtr, ref ReturnBufferLength as int, ref ProtocolStatus as int) as int:
        pass


    [DllImport('secur32.dll', EntryPoint: 'LsaCallAuthenticationPackage', SetLastError: false)]
    private static def LsaCallAuthenticationPackage_KERB_RETRIEVE_TKT(LsaHandle as IntPtr, AuthenticationPackage as int, ref ProtocolSubmitBuffer as KERB_RETRIEVE_TKT_REQUEST, SubmitBufferLength as int, ref ProtocolReturnBuffer as IntPtr, ref ReturnBufferLength as int, ref ProtocolStatus as int) as int:
        pass


    [DllImport('secur32.dll', EntryPoint: 'LsaCallAuthenticationPackage', SetLastError: false)]
    private static def LsaCallAuthenticationPackage_KERB_RETRIEVE_TKT_UNI(LsaHandle as IntPtr, AuthenticationPackage as int, ref ProtocolSubmitBuffer as KERB_RETRIEVE_TKT_REQUEST_UNI, SubmitBufferLength as int, ref ProtocolReturnBuffer as IntPtr, ref ReturnBufferLength as int, ref ProtocolStatus as int) as int:
        pass


    [DllImport('secur32.dll', SetLastError: false)]
    private static def LsaFreeReturnBuffer(buffer as IntPtr) as uint:
        pass


    [DllImport('Secur32.dll', SetLastError: false)]
    private static def LsaEnumerateLogonSessions(ref LogonSessionCount as UInt64, ref LogonSessionList as IntPtr) as uint:
        pass


    [DllImport('Secur32.dll', SetLastError: false)]
    private static def LsaGetLogonSessionData(luid as IntPtr, ref ppLogonSessionData as IntPtr) as uint:
        pass


    // for GetSystem()
    [DllImport('advapi32.dll', SetLastError: true)]
    private static def OpenProcessToken(ProcessHandle as IntPtr, DesiredAccess as UInt32, ref TokenHandle as IntPtr) as bool:
        pass


    [DllImport('advapi32.dll')]
    public static def DuplicateToken(ExistingTokenHandle as IntPtr, SECURITY_IMPERSONATION_LEVEL as int, ref DuplicateTokenHandle as IntPtr) as bool:
        pass


    [DllImport('advapi32.dll', SetLastError: true)]
    private static def ImpersonateLoggedOnUser(hToken as IntPtr) as bool:
        pass


    [DllImport('advapi32.dll', SetLastError: true)]
    private static def RevertToSelf() as bool:
        pass


    [DllImport('kernel32.dll', SetLastError: true)]
    private static def CloseHandle(hObject as IntPtr) as bool:
        pass


    [DllImport('kernel32.dll')]
    private static def LocalAlloc(uFlags as uint, uBytes as uint) as IntPtr:
        pass


    [DllImport('kernel32.dll', EntryPoint: 'CopyMemory', SetLastError: false)]
    public static def CopyMemory(dest as IntPtr, src as IntPtr, count as uint):
        pass


    [DllImport('IpHlpApi.dll')]
    internal static def GetIpNetTable(pIpNetTable as IntPtr, [MarshalAs(UnmanagedType.U4)] ref pdwSize as int, bOrder as bool) as int:
        pass


    [DllImport('IpHlpApi.dll', SetLastError: true, CharSet: CharSet.Auto)]
    internal static def FreeMibTable(plpNetTable as IntPtr) as int:
        pass


    [DllImport('advapi32.dll', CharSet: CharSet.Auto, SetLastError: true)]
    private static def LookupAccountSid(lpSystemName as string, [MarshalAs(UnmanagedType.LPArray)] Sid as (byte), lpName as StringBuilder, ref cchName as uint, ReferencedDomainName as StringBuilder, ref cchReferencedDomainName as uint, ref peUse as SID_NAME_USE) as bool:
        pass


    // PInvoke structures/contants
    public static final SE_GROUP_LOGON_ID as uint = 3221225472L

    // from winnt.h
    public static final TokenGroups = 2

    // from TOKEN_INFORMATION_CLASS
    private enum TOKEN_INFORMATION_CLASS:

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


    [StructLayout(LayoutKind.Sequential)]
    public struct SID_AND_ATTRIBUTES:

        public Sid as IntPtr

        public Attributes as uint


    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_GROUPS:

        public GroupCount as int

        [MarshalAs(UnmanagedType.ByValArray, SizeConst: 1)]
        public Groups as (SID_AND_ATTRIBUTES)


    protected struct TOKEN_PRIVILEGES:

        public PrivilegeCount as UInt32

        [MarshalAs(UnmanagedType.ByValArray, SizeConst: 35)]
        public Privileges as (LUID_AND_ATTRIBUTES)


    [StructLayout(LayoutKind.Sequential)]
    protected struct LUID_AND_ATTRIBUTES:

        public Luid as LUID

        public Attributes as UInt32


    [StructLayout(LayoutKind.Sequential)]
    protected struct LUID:

        public LowPart as uint

        public HighPart as int


    [Flags]
    public enum FirewallProfiles:

        DOMAIN = 1

        PRIVATE = 2

        PUBLIC = 4

        ALL = 2147483647


    [Flags]
    public enum LuidAttributes:

        DISABLED = 0

        SE_PRIVILEGE_ENABLED_BY_DEFAULT = 1

        SE_PRIVILEGE_ENABLED = 2

        SE_PRIVILEGE_REMOVED = 4


    private enum SID_NAME_USE:

        SidTypeUser = 1

        SidTypeGroup

        SidTypeDomain

        SidTypeAlias

        SidTypeWellKnownGroup

        SidTypeDeletedAccount

        SidTypeInvalid

        SidTypeUnknown

        SidTypeComputer


    [StructLayout(LayoutKind.Sequential)]
    private struct WTS_SESSION_INFO:

        public SessionID as Int32


        [MarshalAs(UnmanagedType.LPStr)]
        public pWinStationName as String


        public State as WTS_CONNECTSTATE_CLASS


    [StructLayout(LayoutKind.Sequential)]
    private struct WTS_SESSION_INFO_1:

        public ExecEnvId as Int32


        public State as WTS_CONNECTSTATE_CLASS


        public SessionID as Int32


        [MarshalAs(UnmanagedType.LPStr)]
        public pSessionName as String


        [MarshalAs(UnmanagedType.LPStr)]
        public pHostName as String


        [MarshalAs(UnmanagedType.LPStr)]
        public pUserName as String


        [MarshalAs(UnmanagedType.LPStr)]
        public pDomainName as String


        [MarshalAs(UnmanagedType.LPStr)]
        public pFarmName as String


    [StructLayout(LayoutKind.Sequential)]
    public struct WTS_CLIENT_ADDRESS:

        public AddressFamily as uint

        [MarshalAs(UnmanagedType.ByValArray, SizeConst: 20)]
        public Address as (byte)


    public enum WTS_CONNECTSTATE_CLASS:

        Active

        Connected

        ConnectQuery

        Shadow

        Disconnected

        Idle

        Listen

        Reset

        Down

        Init


    public enum WTS_INFO_CLASS:

        WTSInitialProgram = 0

        WTSApplicationName = 1

        WTSWorkingDirectory = 2

        WTSOEMId = 3

        WTSSessionId = 4

        WTSUserName = 5

        WTSWinStationName = 6

        WTSDomainName = 7

        WTSConnectState = 8

        WTSClientBuildNumber = 9

        WTSClientName = 10

        WTSClientDirectory = 11

        WTSClientProductId = 12

        WTSClientHardwareId = 13

        WTSClientAddress = 14

        WTSClientDisplay = 15

        WTSClientProtocolType = 16

        WTSIdleTime = 17

        WTSLogonTime = 18

        WTSIncomingBytes = 19

        WTSOutgoingBytes = 20

        WTSIncomingFrames = 21

        WTSOutgoingFrames = 22

        WTSClientInfo = 23

        WTSSessionInfo = 24

        WTSSessionInfoEx = 25

        WTSConfigInfo = 26

        WTSValidationInfo = 27

        WTSSessionAddressV4 = 28

        WTSIsRemoteSession = 29


    public enum TCP_TABLE_CLASS:

        TCP_TABLE_BASIC_LISTENER

        TCP_TABLE_BASIC_CONNECTIONS

        TCP_TABLE_BASIC_ALL

        TCP_TABLE_OWNER_PID_LISTENER

        TCP_TABLE_OWNER_PID_CONNECTIONS

        TCP_TABLE_OWNER_PID_ALL

        TCP_TABLE_OWNER_MODULE_LISTENER

        TCP_TABLE_OWNER_MODULE_CONNECTIONS

        TCP_TABLE_OWNER_MODULE_ALL


    public enum UDP_TABLE_CLASS:

        UDP_TABLE_BASIC

        UDP_TABLE_OWNER_PID

        UDP_TABLE_OWNER_MODULE


    [StructLayout(LayoutKind.Sequential)]
    public struct SC_SERVICE_TAG_QUERY:

        public ProcessId as uint

        public ServiceTag as uint

        public Unknown as uint

        public Buffer as IntPtr


    public enum SC_SERVICE_TAG_QUERY_TYPE:

        ServiceNameFromTagInformation = 1

        ServiceNamesReferencingModuleInformation = 2

        ServiceNameTagMappingInformation = 3


    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_TCPTABLE_OWNER_MODULE:

        public NumEntries as uint

        private Table as MIB_TCPROW_OWNER_MODULE


    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_TCPROW_OWNER_MODULE:

        public final State as MIB_TCP_STATE

        public final LocalAddr as uint

        private final LocalPort1 as byte

        private final LocalPort2 as byte

        private final LocalPort3 as byte

        private final LocalPort4 as byte

        public final RemoteAddr as uint

        private final RemotePort1 as byte

        private final RemotePort2 as byte

        private final RemotePort3 as byte

        private final RemotePort4 as byte

        public final OwningPid as uint

        public final CreateTimestamp as UInt64

        public final OwningModuleInfo0 as UInt64

        public final OwningModuleInfo1 as UInt64

        public final OwningModuleInfo2 as UInt64

        public final OwningModuleInfo3 as UInt64

        public final OwningModuleInfo4 as UInt64

        public final OwningModuleInfo5 as UInt64

        public final OwningModuleInfo6 as UInt64

        public final OwningModuleInfo7 as UInt64

        public final OwningModuleInfo8 as UInt64

        public final OwningModuleInfo9 as UInt64

        public final OwningModuleInfo10 as UInt64

        public final OwningModuleInfo11 as UInt64

        public final OwningModuleInfo12 as UInt64

        public final OwningModuleInfo13 as UInt64

        public final OwningModuleInfo14 as UInt64

        public final OwningModuleInfo15 as UInt64



        public LocalPort as ushort:
            get:
                return BitConverter.ToUInt16((of byte: LocalPort2, LocalPort1), 0)


        public LocalAddress as IPAddress:
            get:
                return IPAddress(LocalAddr)


        public RemoteAddress as IPAddress:
            get:
                return IPAddress(RemoteAddr)


        public RemotePort as ushort:
            get:
                return BitConverter.ToUInt16((of byte: RemotePort2, RemotePort1), 0)


    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_UDPTABLE_OWNER_MODULE:

        public NumEntries as uint

        private Table as MIB_UDPROW_OWNER_MODULE


    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_UDPROW_OWNER_MODULE:

        public final LocalAddr as uint

        private final LocalPort1 as byte

        private final LocalPort2 as byte

        private final LocalPort3 as byte

        private final LocalPort4 as byte

        public final OwningPid as uint

        public final CreateTimestamp as UInt64

        public final SpecificPortBind_Flags as UInt32

        // public readonly UInt32 Flags;
        public final OwningModuleInfo0 as UInt64

        public final OwningModuleInfo1 as UInt64

        public final OwningModuleInfo2 as UInt64

        public final OwningModuleInfo3 as UInt64

        public final OwningModuleInfo4 as UInt64

        public final OwningModuleInfo5 as UInt64

        public final OwningModuleInfo6 as UInt64

        public final OwningModuleInfo7 as UInt64

        public final OwningModuleInfo8 as UInt64

        public final OwningModuleInfo9 as UInt64

        public final OwningModuleInfo10 as UInt64

        public final OwningModuleInfo11 as UInt64

        public final OwningModuleInfo12 as UInt64

        public final OwningModuleInfo13 as UInt64

        public final OwningModuleInfo14 as UInt64

        public final OwningModuleInfo15 as UInt64


        public LocalPort as ushort:
            get:
                return BitConverter.ToUInt16((of byte: LocalPort2, LocalPort1), 0)


        public LocalAddress as IPAddress:
            get:
                return IPAddress(LocalAddr)


    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_TCPROW_OWNER_PID:

        public state as uint

        public localAddr as uint

        public localPort1 as byte

        public localPort2 as byte

        public localPort3 as byte

        public localPort4 as byte

        public remoteAddr as uint

        public remotePort1 as byte

        public remotePort2 as byte

        public remotePort3 as byte

        public remotePort4 as byte

        public owningPid as int


        public LocalPort as ushort:
            get:
                return BitConverter.ToUInt16((of byte: localPort2, localPort1), 0)


        public LocalAddress as IPAddress:
            get:
                return IPAddress(localAddr)


        public RemoteAddress as IPAddress:
            get:
                return IPAddress(remoteAddr)


        public RemotePort as ushort:
            get:
                return BitConverter.ToUInt16((of byte: remotePort2, remotePort1), 0)


        public State as MIB_TCP_STATE:
            get:
                return (state cast MIB_TCP_STATE)


    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_UDPROW_OWNER_PID:

        public localAddr as uint

        //[MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public localPort1 as byte

        public localPort2 as byte

        public localPort3 as byte

        public localPort4 as byte

        public owningPid as int


        public LocalPort as ushort:
            get:
                return BitConverter.ToUInt16((of byte: localPort2, localPort1), 0)


        public LocalAddress as IPAddress:
            get:
                return IPAddress(localAddr)


    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_TCPTABLE_OWNER_PID:

        public dwNumEntries as uint

        private table as MIB_TCPROW_OWNER_PID


    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_UDPTABLE_OWNER_PID:

        public dwNumEntries as uint

        private table as MIB_TCPROW_OWNER_PID


    public enum MIB_TCP_STATE:

        CLOSED = 1

        LISTEN = 2

        SYN_SENT = 3

        SYN_RCVD = 4

        ESTAB = 5

        FIN_WAIT1 = 6

        FIN_WAIT2 = 7

        CLOSE_WAIT = 8

        CLOSING = 9

        LAST_ACK = 10

        TIME_WAIT = 11

        DELETE_TCB = 12


    [StructLayout(LayoutKind.Sequential)]
    public struct LSA_STRING_IN:

        public Length as UInt16

        public MaximumLength as UInt16

        public Buffer as string


    [StructLayout(LayoutKind.Sequential)]
    public struct LSA_STRING_OUT:

        public Length as UInt16

        public MaximumLength as UInt16

        public Buffer as IntPtr


    [StructLayout(LayoutKind.Sequential)]
    public struct UNICODE_STRING(IDisposable):

        public Length as ushort

        public MaximumLength as ushort

        public buffer as IntPtr


        public def constructor(s as string):
            Length = ((s.Length * 2) cast ushort)
            MaximumLength = ((Length + 2) cast ushort)
            buffer = Marshal.StringToHGlobalUni(s)


        public def Dispose():
            Marshal.FreeHGlobal(buffer)
            buffer = IntPtr.Zero


        public override def ToString() as string:
            return Marshal.PtrToStringUni(buffer)

    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_HANDLE:

        public LowPart as IntPtr

        public HighPart as IntPtr

        public def constructor(dummy as int):
            LowPart = (HighPart = IntPtr.Zero)


    [StructLayout(LayoutKind.Sequential)]
    public struct KERB_TICKET_CACHE_INFO:

        public ServerName as LSA_STRING_OUT

        public RealmName as LSA_STRING_OUT

        public StartTime as Int64

        public EndTime as Int64

        public RenewTime as Int64

        public EncryptionType as Int32

        public TicketFlags as UInt32


    [StructLayout(LayoutKind.Sequential)]
    public struct KERB_TICKET_CACHE_INFO_EX:

        public ClientName as LSA_STRING_OUT

        public ClientRealm as LSA_STRING_OUT

        public ServerName as LSA_STRING_OUT

        public ServerRealm as LSA_STRING_OUT

        public StartTime as Int64

        public EndTime as Int64

        public RenewTime as Int64

        public EncryptionType as Int32

        public TicketFlags as UInt32


    [StructLayout(LayoutKind.Sequential)]
    private struct KERB_QUERY_TKT_CACHE_RESPONSE:

        public MessageType as KERB_PROTOCOL_MESSAGE_TYPE

        public CountOfTickets as int

        // public KERB_TICKET_CACHE_INFO[] Tickets;
        public Tickets as IntPtr


    [StructLayout(LayoutKind.Sequential)]
    private struct KERB_QUERY_TKT_CACHE_EX_RESPONSE:

        public MessageType as KERB_PROTOCOL_MESSAGE_TYPE

        public CountOfTickets as int

        // public KERB_TICKET_CACHE_INFO[] Tickets;
        public Tickets as IntPtr


    [StructLayout(LayoutKind.Sequential)]
    private struct KERB_QUERY_TKT_CACHE_REQUEST:

        public MessageType as KERB_PROTOCOL_MESSAGE_TYPE

        public LogonId as LUID


    [StructLayout(LayoutKind.Sequential)]
    private struct KERB_RETRIEVE_TKT_REQUEST:

        public MessageType as KERB_PROTOCOL_MESSAGE_TYPE

        public LogonId as LUID

        public TargetName as LSA_STRING_IN

        public TicketFlags as UInt64

        public CacheOptions as KERB_CACHE_OPTIONS

        public EncryptionType as Int64

        public CredentialsHandle as SECURITY_HANDLE


    [StructLayout(LayoutKind.Sequential)]
    private struct KERB_RETRIEVE_TKT_REQUEST_UNI:

        public MessageType as KERB_PROTOCOL_MESSAGE_TYPE

        public LogonId as LUID

        public TargetName as UNICODE_STRING

        public TicketFlags as UInt64

        public CacheOptions as KERB_CACHE_OPTIONS

        public EncryptionType as Int64

        public CredentialsHandle as SECURITY_HANDLE


    [StructLayout(LayoutKind.Sequential)]
    private struct KERB_CRYPTO_KEY:

        public KeyType as Int32

        public Length as Int32

        public Value as IntPtr


    [StructLayout(LayoutKind.Sequential)]
    private struct KERB_EXTERNAL_NAME:

        public NameType as Int16

        public NameCount as UInt16

        public Names as LSA_STRING_OUT


    [StructLayout(LayoutKind.Sequential)]
    private struct KERB_EXTERNAL_TICKET:

        public ServiceName as IntPtr

        public TargetName as IntPtr

        public ClientName as IntPtr

        public DomainName as LSA_STRING_OUT

        public TargetDomainName as LSA_STRING_OUT

        public AltTargetDomainName as LSA_STRING_OUT

        public SessionKey as KERB_CRYPTO_KEY

        public TicketFlags as UInt32

        public Flags as UInt32

        public KeyExpirationTime as Int64

        public StartTime as Int64

        public EndTime as Int64

        public RenewUntil as Int64

        public TimeSkew as Int64

        public EncodedTicketSize as Int32

        public EncodedTicket as IntPtr


    [StructLayout(LayoutKind.Sequential)]
    private struct KERB_RETRIEVE_TKT_RESPONSE:
        public Ticket as KERB_EXTERNAL_TICKET


    private enum SECURITY_LOGON_TYPE:

        Interactive = 2

        // logging on interactively.
        Network

        // logging using a network.
        Batch

        // logon for a batch process.
        Service

        // logon for a service account.
        Proxy

        // Not supported.
        Unlock

        // Tattempt to unlock a workstation.
        NetworkCleartext

        // network logon with cleartext credentials
        NewCredentials

        // caller can clone its current token and specify new credentials for outbound connections
        RemoteInteractive

        // terminal server session that is both remote and interactive
        CachedInteractive

        // attempt to use the cached credentials without going out across the network
        CachedRemoteInteractive

        // same as RemoteInteractive, except used internally for auditing purposes
        CachedUnlock
        // attempt to unlock a workstation


    [StructLayout(LayoutKind.Sequential)]
    private struct SECURITY_LOGON_SESSION_DATA:

        public Size as UInt32

        public LoginID as LUID

        public Username as LSA_STRING_OUT

        public LoginDomain as LSA_STRING_OUT

        public AuthenticationPackage as LSA_STRING_OUT

        public LogonType as UInt32

        public Session as UInt32

        public PSiD as IntPtr

        public LoginTime as UInt64

        public LogonServer as LSA_STRING_OUT

        public DnsDomainName as LSA_STRING_OUT

        public Upn as LSA_STRING_OUT


    public static final MAXLEN_PHYSADDR = 8

    public static final ERROR_SUCCESS = 0

    public static final ERROR_INSUFFICIENT_BUFFER = 122


    [StructLayout(LayoutKind.Sequential)]
    internal struct MIB_IPNETROW:

        [MarshalAs(UnmanagedType.U4)]
        public dwIndex as int

        [MarshalAs(UnmanagedType.U4)]
        public dwPhysAddrLen as int

        [MarshalAs(UnmanagedType.U1)]
        public mac0 as byte

        [MarshalAs(UnmanagedType.U1)]
        public mac1 as byte

        [MarshalAs(UnmanagedType.U1)]
        public mac2 as byte

        [MarshalAs(UnmanagedType.U1)]
        public mac3 as byte

        [MarshalAs(UnmanagedType.U1)]
        public mac4 as byte

        [MarshalAs(UnmanagedType.U1)]
        public mac5 as byte

        [MarshalAs(UnmanagedType.U1)]
        public mac6 as byte

        [MarshalAs(UnmanagedType.U1)]
        public mac7 as byte

        [MarshalAs(UnmanagedType.U4)]
        public dwAddr as int

        [MarshalAs(UnmanagedType.U4)]
        public dwType as int


    public enum ArpEntryType:

        Other = 1

        Invalid = 2

        Dynamic = 3

        Static = 4



    // helpers (registry, UNC paths, etc.)

    public static def OpenServer(Name as String) as IntPtr:
        server as IntPtr = WTSOpenServer(Name)
        return server

    public static def CloseServer(ServerHandle as IntPtr):
        WTSCloseServer(ServerHandle)


    public static def TranslateSid(Sid as string) as string:
        // adapted from http://www.pinvoke.net/default.aspx/advapi32.LookupAccountSid
        accountSid = SecurityIdentifier(Sid)
        accountSidByes as (byte) = array(byte, accountSid.BinaryLength)
        accountSid.GetBinaryForm(accountSidByes, 0)

        name = StringBuilder()
        cchName = (name.Capacity cast uint)
        referencedDomainName = StringBuilder()
        cchReferencedDomainName = (referencedDomainName.Capacity cast uint)
        sidUse as SID_NAME_USE

        err = 0
        if not LookupAccountSid(null, accountSidByes, name, cchName, referencedDomainName, cchReferencedDomainName, sidUse):
            err = System.Runtime.InteropServices.Marshal.GetLastWin32Error()
            if err == ERROR_INSUFFICIENT_BUFFER:
                name.EnsureCapacity((cchName cast int))
                referencedDomainName.EnsureCapacity((cchReferencedDomainName cast int))
                err = 0
                if not LookupAccountSid(null, accountSidByes, name, cchName, referencedDomainName, cchReferencedDomainName, sidUse):
                    err = System.Runtime.InteropServices.Marshal.GetLastWin32Error()
        if err == 0:
            return String.Format('{0}\\{1}', referencedDomainName.ToString(), name.ToString())
        else:
            return ''


    public static def PrintLogo():
        Console.WriteLine('\r\n\r\n                        %&&@@@&&                                                                                  ')
        Console.WriteLine('                        &&&&&&&%%%,                       #&&@@@@@@%%%%%%###############%                         ')
        Console.WriteLine('                        &%&   %&%%                        &////(((&%%%%%#%################//((((###%%%%%%%%%%%%%%%')
        Console.WriteLine('%%%%%%%%%%%######%%%#%%####%  &%%**#                      @////(((&%%%%%%######################(((((((((((((((((((')
        Console.WriteLine('#%#%%%%%%%#######%#%%#######  %&%,,,,,,,,,,,,,,,,         @////(((&%%%%%#%#####################(((((((((((((((((((')
        Console.WriteLine('#%#%%%%%%#####%%#%#%%#######  %%%,,,,,,  ,,.   ,,         @////(((&%%%%%%%######################(#(((#(#((((((((((')
        Console.WriteLine('#####%%%####################  &%%......  ...   ..         @////(((&%%%%%%%###############%######((#(#(####((((((((')
        Console.WriteLine('#######%##########%#########  %%%......  ...   ..         @////(((&%%%%%#########################(#(#######((#####')
        Console.WriteLine('###%##%%####################  &%%...............          @////(((&%%%%%%%%##############%#######(#########((#####')
        Console.WriteLine('#####%######################  %%%..                       @////(((&%%%%%%%################                        ')
        Console.WriteLine('                        &%&   %%%%%      Seatbelt         %////(((&%%%%%%%%#############*                         ')
        Console.WriteLine('                        &%%&&&%%%%%        v0.2.0         ,(((&%%%%%%%%%%%%%%%%%,                                 ')
        Console.WriteLine('                         #%%%%##,                                                                                 \r\n\r\n')


    public static def GetRegValue(hive as string, path as string, value as string) as string:
        // returns a single registry value under the specified path in the specified hive (HKLM/HKCU)
        regKey as duck
        regKeyValue = ''
        if hive == 'HKCU':
            regKey = Registry.CurrentUser.OpenSubKey(path)
            if regKey is not null:
                regKeyValue = String.Format('{0}', regKey.GetValue(value))
            return regKeyValue
        elif hive == 'HKU':
            regKey = Registry.Users.OpenSubKey(path)
            if regKey is not null:
                regKeyValue = String.Format('{0}', regKey.GetValue(value))
            return regKeyValue
        else:
            regKey = Registry.LocalMachine.OpenSubKey(path)
            if regKey is not null:
                regKeyValue = String.Format('{0}', regKey.GetValue(value))
            return regKeyValue


    public static def GetRegValueBytes(hive as string, path as string, value as string) as (byte):
        // returns a byte array of single registry value under the specified path in the specified hive (HKLM/HKCU)
        regKey as duck
        regKeyValue as (byte) = null
        if hive == 'HKCU':
            regKey = Registry.CurrentUser.OpenSubKey(path)
            if regKey is not null:
                regKeyValue = (regKey.GetValue(value) cast (byte))
            return regKeyValue
        elif hive == 'HKU':
            regKey = Registry.Users.OpenSubKey(path)
            if regKey is not null:
                regKeyValue = (regKey.GetValue(value) cast (byte))
            return regKeyValue
        else:
            regKey = Registry.LocalMachine.OpenSubKey(path)
            if regKey is not null:
                regKeyValue = (regKey.GetValue(value) cast (byte))
            return regKeyValue


    public static def GetRegValues(hive as string, path as string) as Dictionary[of string, object]:
        // returns all registry values under the specified path in the specified hive (HKLM/HKCU)
        valueNames as duck
        keyValuePairs as Dictionary[of string, object] = null
        try:
            if hive == 'HKCU':
                using regKeyValues = Registry.CurrentUser.OpenSubKey(path):
                    if regKeyValues is not null:
                        valueNames = regKeyValues.GetValueNames()
                        keyValuePairs = valueNames.ToDictionary({ name | return name }, regKeyValues.GetValue)
            elif hive == 'HKU':
                using regKeyValues = Registry.Users.OpenSubKey(path):
                    if regKeyValues is not null:
                        valueNames = regKeyValues.GetValueNames()
                        keyValuePairs = valueNames.ToDictionary({ name | return name }, regKeyValues.GetValue)
            else:
                using regKeyValues = Registry.LocalMachine.OpenSubKey(path):
                    if regKeyValues is not null:
                        valueNames = regKeyValues.GetValueNames()
                        keyValuePairs = valueNames.ToDictionary({ name | return name }, regKeyValues.GetValue)
            return keyValuePairs
        except :
            return null


    public static def GetRegSubkeys(hive as string, path as string) as (string):
        // returns an array of the subkeys names under the specified path in the specified hive (HKLM/HKCU/HKU)
        try:
            myKey as Microsoft.Win32.RegistryKey = null
            if hive == 'HKLM':
                myKey = Registry.LocalMachine.OpenSubKey(path)
            elif hive == 'HKU':
                myKey = Registry.Users.OpenSubKey(path)
            else:
                myKey = Registry.CurrentUser.OpenSubKey(path)
            subkeyNames as (String) = myKey.GetSubKeyNames()
            return myKey.GetSubKeyNames()
        except :
            return array(string, 0)


    public static def GetUNCPath(originalPath as string) as string:
        // uses WNetGetConnection to map a drive letter to a possible UNC mount path
        // Pulled from @ambyte's gist at https://gist.github.com/ambyte/01664dc7ee576f69042c

        sb = StringBuilder(512)
        size as int = sb.Capacity

        // look for the {LETTER}: combination ...
        if (originalPath.Length > 2) and (originalPath[1] == char(':')):
            // don't use char.IsLetter here - as that can be misleading
            // the only valid drive letters are a-z && A-Z.
            c as char = originalPath[0]
            if ((c >= char('a')) and (c <= char('z'))) or ((c >= char('A')) and (c <= char('Z'))):
                error as int = WNetGetConnection(originalPath.Substring(0, 2), sb, size)
                if error == 0:
                    dir = DirectoryInfo(originalPath)

                    path as string = Path.GetFullPath(originalPath).Substring(Path.GetPathRoot(originalPath).Length)
                    return Path.Combine(sb.ToString().TrimEnd(), path)

        return originalPath


    public static def IsHighIntegrity() as bool:
        // returns true if the current process is running with adminstrative privs in a high integrity context
        identity as WindowsIdentity = WindowsIdentity.GetCurrent()
        principal = WindowsPrincipal(identity)
        return principal.IsInRole(WindowsBuiltInRole.Administrator)


    public static def GetLocalGroupMembers(groupName as string) as (string):
        // returns the "DOMAIN\user" members for a specified local group name
        // adapted from boboes' code at https://stackoverflow.com/questions/33935825/pinvoke-netlocalgroupgetmembers-runs-into-fatalexecutionengineerror/33939889#33939889

        computerName as string = null
        // null for the local machine
        EntriesRead as int
        TotalEntries as int
        Resume as IntPtr
        bufPtr as IntPtr

        retVal as uint = NetworkAPI.NetLocalGroupGetMembers(computerName, groupName, 2, bufPtr, -1, EntriesRead, TotalEntries, Resume)

        if retVal != 0:
            if retVal == NetworkAPI.ERROR_ACCESS_DENIED:
                Console.WriteLine('Access denied')
                return null
            if retVal == NetworkAPI.ERROR_MORE_DATA:
                Console.WriteLine('ERROR_MORE_DATA')
                return null
            if retVal == NetworkAPI.ERROR_NO_SUCH_ALIAS:
                Console.WriteLine('Group not found')
                return null
            if retVal == NetworkAPI.NERR_InvalidComputer:
                Console.WriteLine('Invalid computer name')
                return null
            if retVal == NetworkAPI.NERR_GroupNotFound:
                Console.WriteLine('Group not found')
                return null
            if retVal == NetworkAPI.SERVER_UNAVAILABLE:
                Console.WriteLine('Server unavailable')
                return null
            Console.WriteLine(('Unexpected NET_API_STATUS: ' + retVal.ToString()))
            return null

        if EntriesRead > 0:
            names as (string) = array(string, EntriesRead)
            Members as (NetworkAPI.LOCALGROUP_MEMBERS_INFO_2) = array(NetworkAPI.LOCALGROUP_MEMBERS_INFO_2, EntriesRead)
            iter as IntPtr = bufPtr
            for i in range(0, EntriesRead):

                Members[i] = (Marshal.PtrToStructure(iter, typeof(NetworkAPI.LOCALGROUP_MEMBERS_INFO_2)) cast NetworkAPI.LOCALGROUP_MEMBERS_INFO_2)

                //x64 safe
                iter = IntPtr((iter.ToInt64() + Marshal.SizeOf(typeof(NetworkAPI.LOCALGROUP_MEMBERS_INFO_2))))

                names[i] = Members[i].lgrmi2_domainandname
            NetworkAPI.NetApiBufferFree(bufPtr)

            return names
        else:
            return null


    public static def GetTokenGroupSIDs() as (string):
        // Returns all SIDs that the current user is a part of, whether they are disabled or not.
        // slightly adapted from https://stackoverflow.com/questions/2146153/how-to-get-the-logon-sid-in-c-sharp/2146418#2146418

        TokenInfLength = 0

        // first call gets length of TokenInformation
        Result as bool = GetTokenInformation(WindowsIdentity.GetCurrent().Token, TOKEN_INFORMATION_CLASS.TokenGroups, IntPtr.Zero, TokenInfLength, TokenInfLength)
        TokenInformation as IntPtr = Marshal.AllocHGlobal(TokenInfLength)
        Result = GetTokenInformation(WindowsIdentity.GetCurrent().Token, TOKEN_INFORMATION_CLASS.TokenGroups, TokenInformation, TokenInfLength, TokenInfLength)

        if not Result:
            Marshal.FreeHGlobal(TokenInformation)
            return null

        groups = (Marshal.PtrToStructure(TokenInformation, typeof(TOKEN_GROUPS)) cast TOKEN_GROUPS)
        userSIDS as (string) = array(string, groups.GroupCount)
        sidAndAttrSize as int = Marshal.SizeOf(SID_AND_ATTRIBUTES())
        for i in range(0, groups.GroupCount):
            sidAndAttributes = (Marshal.PtrToStructure(IntPtr(((TokenInformation.ToInt64() + (i * sidAndAttrSize)) + IntPtr.Size)), typeof(SID_AND_ATTRIBUTES)) cast SID_AND_ATTRIBUTES)

            pstr as IntPtr = IntPtr.Zero
            ConvertSidToStringSid(sidAndAttributes.Sid, pstr)
            userSIDS[i] = Marshal.PtrToStringAuto(pstr)
            LocalFree(pstr)

        Marshal.FreeHGlobal(TokenInformation)
        return userSIDS


    public static def GetSystem() as bool:
        // helper to elevate to SYSTEM for Kerberos ticket enumeration via token impersonation

        if IsHighIntegrity():
            hToken as IntPtr = IntPtr.Zero

            // Open winlogon's token with TOKEN_DUPLICATE accesss so ca can make a copy of the token with DuplicateToken
            processes as (Process) = Process.GetProcessesByName('winlogon')
            handle as IntPtr = processes[0].Handle

            // TOKEN_DUPLICATE = 0x0002
            success as bool = OpenProcessToken(handle, 2, hToken)
            if not success:
                //Console.WriteLine("OpenProcessToken failed!");
                return false

            // make a copy of the NT AUTHORITY\SYSTEM token from winlogon
            // 2 == SecurityImpersonation
            hDupToken as IntPtr = IntPtr.Zero
            success = DuplicateToken(hToken, 2, hDupToken)
            if not success:
                //Console.WriteLine("DuplicateToken failed!");
                return false

            success = ImpersonateLoggedOnUser(hDupToken)
            if not success:
                //Console.WriteLine("ImpersonateLoggedOnUser failed!");
                return false

            // clean up the handles we created
            CloseHandle(hToken)
            CloseHandle(hDupToken)

            name as string = System.Security.Principal.WindowsIdentity.GetCurrent().Name
            if name != 'NT AUTHORITY\\SYSTEM':
                return false

            return true
        else:
            return false


    public static def LsaRegisterLogonProcessHelper() as IntPtr:
        // helper that establishes a connection to the LSA server and verifies that the caller is a logon application
        //  used for Kerberos ticket enumeration

        logonProcessName = 'User32LogonProcesss'
        LSAString as LSA_STRING_IN
        lsaHandle as IntPtr = IntPtr.Zero
        securityMode as UInt64 = 0

        LSAString.Length = (logonProcessName.Length cast ushort)
        LSAString.MaximumLength = ((logonProcessName.Length + 1) cast ushort)
        LSAString.Buffer = logonProcessName

        ret as int = LsaRegisterLogonProcess(LSAString, lsaHandle, securityMode)

        return lsaHandle


    public static def IsLocalAdmin() as bool:
        // checks if the "S-1-5-32-544" in the current token groups set, meaning the user is a local administrator
        SIDs as (string) = GetTokenGroupSIDs()

        for SID as string in SIDs:
            if SID == 'S-1-5-32-544':
                return true
        return false


    public static def IsVirtualMachine() as bool:
        // returns true if the system is likely a virtual machine
        // Adapted from RobSiklos' code from https://stackoverflow.com/questions/498371/how-to-detect-if-my-application-is-running-in-a-virtual-machine/11145280#11145280

        using searcher = System.Management.ManagementObjectSearcher('Select * from Win32_ComputerSystem'):
            using items = searcher.Get():
                for item as duck in items:
                    manufacturer as string = item['Manufacturer'].ToString().ToLower()
                    if (((manufacturer == 'microsoft corporation') and item['Model'].ToString().ToUpperInvariant().Contains('VIRTUAL')) or manufacturer.Contains('vmware')) or (item['Model'].ToString() == 'VirtualBox'):
                        return true
        return false


    public static def CheckAccess(Path as string, AccessRight as FileSystemRights) as bool:
        // checks if the current user has the specified AccessRight to the specified file or folder
        // adapted from https://stackoverflow.com/questions/1410127/c-sharp-test-if-user-has-write-access-to-a-folder/21996345#21996345

        if string.IsNullOrEmpty(Path):
            return false

        try:
            rules as AuthorizationRuleCollection = Directory.GetAccessControl(Path).GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier))
            identity as WindowsIdentity = WindowsIdentity.GetCurrent()

            for rule as FileSystemAccessRule in rules:
                if identity.Groups.Contains(rule.IdentityReference):
                    if (AccessRight & rule.FileSystemRights) == AccessRight:
                        if rule.AccessControlType == AccessControlType.Allow:
                            return true
        except :
            pass

        return false


    public static def CheckModifiableAccess(Path as string) as bool:
        // checks if the current user has rights to modify the given file/directory
        // adapted from https://stackoverflow.com/questions/1410127/c-sharp-test-if-user-has-write-access-to-a-folder/21996345#21996345

        if string.IsNullOrEmpty(Path):
            return false
        // TODO: check if file exists, check file's parent folder

        ModifyRights as (FileSystemRights) = (FileSystemRights.ChangePermissions, FileSystemRights.FullControl, FileSystemRights.Modify, FileSystemRights.TakeOwnership, FileSystemRights.Write, FileSystemRights.WriteData, FileSystemRights.CreateDirectories, FileSystemRights.CreateFiles)

        paths = ArrayList()
        paths.Add(Path)

        try:
            attr as FileAttributes = System.IO.File.GetAttributes(Path)
            if (attr & FileAttributes.Directory) != FileAttributes.Directory:
                parentFolder as string = System.IO.Path.GetDirectoryName(Path)
                paths.Add(parentFolder)
        except :
            return false


        try:
            for candidatePath as string in paths:
                rules as AuthorizationRuleCollection = Directory.GetAccessControl(candidatePath).GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier))
                identity as WindowsIdentity = WindowsIdentity.GetCurrent()

                for rule as FileSystemAccessRule in rules:
                    if identity.Groups.Contains(rule.IdentityReference):
                        for AccessRight as FileSystemRights in ModifyRights:
                            if (AccessRight & rule.FileSystemRights) == AccessRight:
                                if rule.AccessControlType == AccessControlType.Allow:
                                    return true
            return false
        except :
            return false


    public static def FindFiles(path as string, patterns as string) as List[of string]:
        // finds files matching one or more patterns under a given path, recursive
        // adapted from http://csharphelper.com/blog/2015/06/find-files-that-match-multiple-patterns-in-c/
        //      pattern: "*pass*;*.png;"

        files as List[of string] = List[of string]()

        try:
            // search every pattern in this directory's files
            for pattern as string in patterns.Split(char(';')):
                files.AddRange(Directory.GetFiles(path, pattern, SearchOption.TopDirectoryOnly))

            // go recurse in all sub-directories
            for directory in Directory.GetDirectories(path):
                files.AddRange(FindFiles(directory, patterns))
        except converterGeneratedName1 as UnauthorizedAccessException:
            pass
        except converterGeneratedName2 as PathTooLongException:
            pass

        return files


    public static def Split(text as string, partLength as int) as IEnumerable[of string]:
        if text is null:
            Console.WriteLine('[ERROR] Split() - singleLineString')
        if partLength < 1:
            Console.WriteLine('[ERROR] Split() - \'columns\' must be greater than 0.')

        partCount = Math.Ceiling(((text.Length cast double) / partLength))
        if partCount < 2:
            yield text
        for i in range(0, partCount):

            index = (i * partLength)
            lengthLeft = Math.Min(partLength, (text.Length - index))
            line as string = text.Substring(index, lengthLeft)
            yield line



    // start of checks

    // system-focused checks
    public static def ListBasicOSInfo():
        // returns basic OS/host information, including:
        //      Windows version information
        //      integrity/admin levels
        //      processor count/architecture
        //      basic user and domain information
        //      whether the system is a VM
        //      etc.

        ProductName as string = GetRegValue('HKLM', 'Software\\Microsoft\\Windows NT\\CurrentVersion', 'ProductName')
        EditionID as string = GetRegValue('HKLM', 'Software\\Microsoft\\Windows NT\\CurrentVersion', 'EditionID')
        ReleaseId as string = GetRegValue('HKLM', 'Software\\Microsoft\\Windows NT\\CurrentVersion', 'ReleaseId')
        BuildBranch as string = GetRegValue('HKLM', 'Software\\Microsoft\\Windows NT\\CurrentVersion', 'BuildBranch')
        CurrentMajorVersionNumber as string = GetRegValue('HKLM', 'Software\\Microsoft\\Windows NT\\CurrentVersion', 'CurrentMajorVersionNumber')
        CurrentVersion as string = GetRegValue('HKLM', 'Software\\Microsoft\\Windows NT\\CurrentVersion', 'CurrentVersion')

        isHighIntegrity as bool = IsHighIntegrity()
        isLocalAdmin as bool = IsLocalAdmin()

        arch as string = System.Environment.GetEnvironmentVariable('PROCESSOR_ARCHITECTURE')
        userName as string = System.Environment.GetEnvironmentVariable('USERNAME')
        ProcessorCount as string = System.Environment.ProcessorCount.ToString()
        isVM as bool = IsVirtualMachine()

        now as DateTime = DateTime.UtcNow
        boot as DateTime = (now - TimeSpan.FromMilliseconds(Environment.TickCount))
        BootTime as DateTime = (boot + TimeSpan.FromMilliseconds(System.Environment.TickCount))

        strHostName as String = Dns.GetHostName()
        properties as IPGlobalProperties = IPGlobalProperties.GetIPGlobalProperties()
        dnsDomain as string = properties.DomainName

        Console.WriteLine('\r\n\r\n=== Basic OS Information ===\r\n')
        Console.WriteLine(String.Format('  {0,-30}:  {1}', 'Hostname', strHostName))
        Console.WriteLine(String.Format('  {0,-30}:  {1}', 'Domain Name', dnsDomain))
        Console.WriteLine(String.Format('  {0,-30}:  {1}', 'Username', WindowsIdentity.GetCurrent().Name))
        Console.WriteLine(String.Format('  {0,-30}:  {1}', 'ProductName', ProductName))
        Console.WriteLine(String.Format('  {0,-30}:  {1}', 'EditionID', EditionID))
        Console.WriteLine(String.Format('  {0,-30}:  {1}', 'ReleaseId', ReleaseId))
        Console.WriteLine(String.Format('  {0,-30}:  {1}', 'BuildBranch', BuildBranch))
        Console.WriteLine(String.Format('  {0,-30}:  {1}', 'CurrentMajorVersionNumber', CurrentMajorVersionNumber))
        Console.WriteLine(String.Format('  {0,-30}:  {1}', 'CurrentVersion', CurrentVersion))
        Console.WriteLine(String.Format('  {0,-30}:  {1}', 'Architecture', arch))
        Console.WriteLine(String.Format('  {0,-30}:  {1}', 'ProcessorCount', ProcessorCount))
        Console.WriteLine(String.Format('  {0,-30}:  {1}', 'IsVirtualMachine', isVM))
        Console.WriteLine(String.Format('  {0,-30}:  {1}', 'BootTime (approx)', BootTime))
        Console.WriteLine(String.Format('  {0,-30}:  {1}', 'HighIntegrity', isHighIntegrity))
        Console.WriteLine(String.Format('  {0,-30}:  {1}', 'IsLocalAdmin', isLocalAdmin))
        if (not isHighIntegrity) and isLocalAdmin:
            Console.WriteLine('    [*] In medium integrity but user is a local administrator- UAC can be bypassed.')


    public static def ListRebootSchedule():
        // queries event IDs 12 (kernel boot) and 13 (kernel shutdown), sorts, and gives reboot schedule
        // grab events from the last X days - 15 for default




        // eventID 12 == start up



        time as date
        lastDays = 15
        Console.WriteLine('\r\n\r\n=== Reboot Schedule (event ID 12/13 from last {0} days) ===\r\n', lastDays)
        events as SortedDictionary[of date, string] = SortedDictionary[of date, string]()
        startTime as DateTime = System.DateTime.Now.AddDays(-lastDays)
        endTime as DateTime = System.DateTime.Now
        query as string = string.Format('*[System/EventID=12] and *[System[TimeCreated[@SystemTime >= \'{0}\']]] and *[System[TimeCreated[@SystemTime <= \'{1}\']]]', startTime.ToUniversalTime().ToString('o'), endTime.ToUniversalTime().ToString('o'))
        eventsQuery = EventLogQuery('System', PathType.LogName, query)
        try:
            logReader = EventLogReader(eventsQuery)
            eventdetail as EventRecord = logReader.ReadEvent()
            goto converterGeneratedName3
            while true:
                eventdetail = logReader.ReadEvent()
                :converterGeneratedName3
                break  unless (eventdetail is not null)
                time = DateTime.Parse(eventdetail.Properties[6].Value.ToString())
                events.Add(time, 'startup')
        except ex as Exception:
            Console.WriteLine('  [X] Exception: {0}', ex.Message)

        // eventID 13 == shutdown
        query2 as string = string.Format('*[System/EventID=13] and *[System[TimeCreated[@SystemTime >= \'{0}\']]] and *[System[TimeCreated[@SystemTime <= \'{1}\']]]', startTime.ToUniversalTime().ToString('o'), endTime.ToUniversalTime().ToString('o'))

        eventsQuery2 = EventLogQuery('System', PathType.LogName, query2)

        try:
            logReader2 = EventLogReader(eventsQuery2)

            eventdetail2 as EventRecord = logReader2.ReadEvent()
            goto converterGeneratedName4
            while true:
                eventdetail2 = logReader2.ReadEvent()
                :converterGeneratedName4
                break  unless (eventdetail2 is not null)
                time = DateTime.Parse(eventdetail2.Properties[0].Value.ToString())
                events.Add(time, 'shutdown')
        except ex as Exception:
            Console.WriteLine('  [X] Exception: {0}', ex.Message)

        for kvp in events:
            Console.WriteLine(String.Format('  {0,-23} :  {1}', kvp.Key, kvp.Value))
            if kvp.Value == 'shutdown':
                Console.WriteLine()


    public static def ListTokenGroupPrivs():
        // Returns all privileges that the current process/user possesses
        // adapted from https://stackoverflow.com/questions/4349743/setting-size-of-token-privileges-luid-and-attributes-array-returned-by-gettokeni

        try:
            Console.WriteLine('\r\n\r\n=== Current Privileges ===\r\n')

            TokenInfLength = 0
            ThisHandle as IntPtr = WindowsIdentity.GetCurrent().Token
            GetTokenInformation(ThisHandle, TOKEN_INFORMATION_CLASS.TokenPrivileges, IntPtr.Zero, TokenInfLength, TokenInfLength)
            TokenInformation as IntPtr = Marshal.AllocHGlobal(TokenInfLength)
            if GetTokenInformation(WindowsIdentity.GetCurrent().Token, TOKEN_INFORMATION_CLASS.TokenPrivileges, TokenInformation, TokenInfLength, TokenInfLength):
                ThisPrivilegeSet = (Marshal.PtrToStructure(TokenInformation, typeof(TOKEN_PRIVILEGES)) cast TOKEN_PRIVILEGES)
                for index in range(0, ThisPrivilegeSet.PrivilegeCount):
                    laa as LUID_AND_ATTRIBUTES = ThisPrivilegeSet.Privileges[index]
                    StrBuilder as System.Text.StringBuilder = System.Text.StringBuilder()
                    LuidNameLen = 0
                    LuidPointer as IntPtr = Marshal.AllocHGlobal(Marshal.SizeOf(laa.Luid))
                    Marshal.StructureToPtr(laa.Luid, LuidPointer, true)
                    LookupPrivilegeName(null, LuidPointer, null, LuidNameLen)
                    StrBuilder.EnsureCapacity((LuidNameLen + 1))
                    if LookupPrivilegeName(null, LuidPointer, StrBuilder, LuidNameLen):
                        Console.WriteLine(String.Format('  {0,43}:  {1}', StrBuilder.ToString(), (laa.Attributes cast LuidAttributes)))
                    Marshal.FreeHGlobal(LuidPointer)
        except ex as Exception:
            Console.WriteLine('  [X] Exception: {0}', ex.Message)


    public static def ListUserEnvVariables():
        try:
            // dumps out current user environment variables
            Console.WriteLine('\r\n\r\n=== User Environment Variables ===\r\n')
            for env as System.Collections.DictionaryEntry in Environment.GetEnvironmentVariables():
                name = (env.Key cast string)
                value = (env.Value cast string)
                Console.WriteLine('  {0,-35} : {1}', name, value)
        except ex as Exception:
            Console.WriteLine('  [X] Exception: {0}', ex.Message)


    public static def ListSystemEnvVariables():
        // dumps out current system environment variables
        Console.WriteLine('\r\n\r\n=== System Environment Variables ===\r\n')
        settings as Dictionary[of string, object] = GetRegValues('HKLM', 'SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment')
        if (settings is not null) and (settings.Count != 0):
            for kvp as KeyValuePair[of string, object] in settings:
                Console.WriteLine('  {0,-35} : {1}', kvp.Key, kvp.Value)


    public static def ListNonstandardServices():
        // lists installed servics that don't have "Microsoft Corporation" as the company name in their file info
        //      or all services if "full" is passed

        if FilterResults.filter:
            Console.WriteLine('\r\n\r\n=== Non Microsoft Services (via WMI) ===\r\n')
        else:
            Console.WriteLine('\r\n\r\n=== All Services (via WMI) ===\r\n')

        try:
            wmiData = ManagementObjectSearcher('root\\cimv2', 'SELECT * FROM win32_service')
            data as ManagementObjectCollection = wmiData.Get()

            for result as ManagementObject in data:
                //OLD - if ((result["PathName"] != null) && ((!FilterResults.filter) || (!Regex.IsMatch(result["PathName"].ToString(), "C:\\\\WINDOWS\\\\", RegexOptions.IgnoreCase))))
                if result['PathName'] is not null:
                    path as Match = Regex.Match(result['PathName'].ToString(), '^\\W*([a-z]:\\\\.+?(\\.exe|\\.dll|\\.sys))\\W*', RegexOptions.IgnoreCase)
                    binaryPath as String = path.Groups[1].ToString()
                    myFileVersionInfo as FileVersionInfo = FileVersionInfo.GetVersionInfo(binaryPath)
                    companyName as string = myFileVersionInfo.CompanyName
                    if (String.IsNullOrEmpty(companyName) or (not FilterResults.filter)) or (not Regex.IsMatch(companyName, '^Microsoft.*', RegexOptions.IgnoreCase)):
                        isDotNet = false
                        try:
                            myAssemblyName as AssemblyName = AssemblyName.GetAssemblyName(binaryPath)
                            isDotNet = true
                        except converterGeneratedName5 as System.IO.FileNotFoundException:
                            pass
                        // System.Console.WriteLine("The file cannot be found.");
                        except exception as System.BadImageFormatException:
                            if Regex.IsMatch(exception.Message, '.*This assembly is built by a runtime newer than the currently loaded runtime and cannot be loaded.*', RegexOptions.IgnoreCase):
                                isDotNet = true
                        except :
                            pass
                        // System.Console.WriteLine("The assembly has already been loaded.");

                        Console.WriteLine('  Name             : {0}', result['Name'])
                        Console.WriteLine('  DisplayName      : {0}', result['DisplayName'])
                        Console.WriteLine('  Company Name     : {0}', companyName)
                        Console.WriteLine('  Description      : {0}', result['Description'])
                        Console.WriteLine('  State            : {0}', result['State'])
                        Console.WriteLine('  StartMode        : {0}', result['StartMode'])
                        Console.WriteLine('  PathName         : {0}', result['PathName'])
                        Console.WriteLine('  IsDotNet         : {0}\r\n', isDotNet)
        except ex as Exception:
            Console.WriteLine('  [X] Exception: {0}', ex.Message)


    public static def ListUserFolders():
        // lists the folders in C:\Users\, showing users who have logged onto the system
        try:
            Console.WriteLine('\r\n\r\n=== User Folders ===\r\n')
            userPath as string = String.Format('{0}\\Users\\', Environment.GetEnvironmentVariable('SystemDrive'))

            dirs as (string) = Directory.GetDirectories(userPath)
            Console.WriteLine('  {0,-35}   {1}', 'Folder', 'Last Modified Time')
            for dir as string in dirs:
                if not (((dir.EndsWith('Public') or dir.EndsWith('Default')) or dir.EndsWith('Default User')) or dir.EndsWith('All Users')):
                    dt as DateTime = Directory.GetLastWriteTime(dir)
                    Console.WriteLine('  {0,-35} : {1}', dir, dt)
        except ex as Exception:
            Console.WriteLine('  [X] Exception: {0}', ex.Message)


    public static def ListUACSystemPolicies():
        // dump out various UAC system policies
        Console.WriteLine('\r\n\r\n=== UAC System Policies ===\r\n')

        ConsentPromptBehaviorAdmin as string = GetRegValue('HKLM', 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System', 'ConsentPromptBehaviorAdmin')
        converterGeneratedName6 = ConsentPromptBehaviorAdmin
        if converterGeneratedName6 == '0':
            Console.WriteLine('  {0,-30} : {1} - No prompting', 'ConsentPromptBehaviorAdmin', ConsentPromptBehaviorAdmin)
        elif converterGeneratedName6 == '1':
            Console.WriteLine('  {0,-30} : {1} - PromptOnSecureDesktop', 'ConsentPromptBehaviorAdmin', ConsentPromptBehaviorAdmin)
        elif converterGeneratedName6 == '2':
            Console.WriteLine('  {0,-30} : {1} - PromptPermitDenyOnSecureDesktop', 'ConsentPromptBehaviorAdmin', ConsentPromptBehaviorAdmin)
        elif converterGeneratedName6 == '3':
            Console.WriteLine('  {0,-30} : {1} - PromptForCredsNotOnSecureDesktop', 'ConsentPromptBehaviorAdmin', ConsentPromptBehaviorAdmin)
        elif converterGeneratedName6 == '4':
            Console.WriteLine('  {0,-30} : {1} - PromptForPermitDenyNotOnSecureDesktop', 'ConsentPromptBehaviorAdmin', ConsentPromptBehaviorAdmin)
        elif converterGeneratedName6 == '5':
            Console.WriteLine('  {0,-30} : {1} - PromptForNonWindowsBinaries', 'ConsentPromptBehaviorAdmin', ConsentPromptBehaviorAdmin)
        else:
            Console.WriteLine('  {0,-30} : PromptForNonWindowsBinaries', 'ConsentPromptBehaviorAdmin')

        EnableLUA as string = GetRegValue('HKLM', 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System', 'EnableLUA')
        Console.WriteLine('  {0,-30} : {1}', 'EnableLUA', EnableLUA)
        if (EnableLUA == '') or (EnableLUA == '0'):
            Console.WriteLine('    [*] EnableLUA != 1, UAC policies disabled.\r\n    [*] Any local account can be used for lateral movement.')

        LocalAccountTokenFilterPolicy as string = GetRegValue('HKLM', 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System', 'LocalAccountTokenFilterPolicy')
        Console.WriteLine('  {0,-30} : {1}', 'LocalAccountTokenFilterPolicy', LocalAccountTokenFilterPolicy)
        if (EnableLUA == '1') and (LocalAccountTokenFilterPolicy == '1'):
            Console.WriteLine('    [*] LocalAccountTokenFilterPolicy set to 1.\r\n    [*] Any local account can be used for lateral movement.')

        FilterAdministratorToken as string = GetRegValue('HKLM', 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System', 'FilterAdministratorToken')
        Console.WriteLine('  {0,-30} : {1}', 'FilterAdministratorToken', FilterAdministratorToken)

        if ((EnableLUA == '1') and (LocalAccountTokenFilterPolicy != '1')) and (FilterAdministratorToken != '1'):
            Console.WriteLine('    [*] LocalAccountTokenFilterPolicy set to 0 and FilterAdministratorToken != 1.\r\n    [*] Only the RID-500 local admin account can be used for lateral movement.')

        if ((EnableLUA == '1') and (LocalAccountTokenFilterPolicy != '1')) and (FilterAdministratorToken == '1'):
            Console.WriteLine('    [*] LocalAccountTokenFilterPolicy set to 0 and FilterAdministratorToken == 1.\r\n    [*] No local accounts can be used for lateral movement.')


    public static def ListPowerShellSettings():
        Console.WriteLine('\r\n\r\n=== PowerShell Settings ===\r\n')

        PowerShellVersion2 as string = GetRegValue('HKLM', 'SOFTWARE\\Microsoft\\PowerShell\\1\\PowerShellEngine', 'PowerShellVersion')
        Console.WriteLine('  {0,-30} : {1}', 'PowerShell v2 Version', PowerShellVersion2)

        PowerShellVersion5 as string = GetRegValue('HKLM', 'SOFTWARE\\Microsoft\\PowerShell\\3\\PowerShellEngine', 'PowerShellVersion')
        Console.WriteLine('  {0,-30} : {1}', 'PowerShell v5 Version', PowerShellVersion5)

        transcriptionSettings as Dictionary[of string, object] = GetRegValues('HKLM', 'SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription')
        Console.WriteLine('\r\n  Transcription Settings:\r\n')
        if (transcriptionSettings is not null) and (transcriptionSettings.Count != 0):
            for kvp as KeyValuePair[of string, object] in transcriptionSettings:
                Console.WriteLine('  {0,30} : {1}\r\n', kvp.Key, kvp.Value)

        moduleLoggingSettings as Dictionary[of string, object] = GetRegValues('HKLM', 'SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging')
        Console.WriteLine('  Module Logging Settings:\r\n')
        if (moduleLoggingSettings is not null) and (moduleLoggingSettings.Count != 0):
            for kvp as KeyValuePair[of string, object] in moduleLoggingSettings:
                Console.WriteLine('  {0,30} : {1}\r\n', kvp.Key, kvp.Value)

        scriptBlockSettings as Dictionary[of string, object] = GetRegValues('HKLM', 'SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging')
        Console.WriteLine('  Scriptblock Logging Settings:\r\n')
        if (scriptBlockSettings is not null) and (scriptBlockSettings.Count != 0):
            for kvp as KeyValuePair[of string, object] in scriptBlockSettings:
                Console.WriteLine('  {0,30} : {1}\r\n', kvp.Key, kvp.Value)


    public static def ListInternetSettings():
        // lists user/system internet settings, including default proxy info

        proxySettings as Dictionary[of string, object] = GetRegValues('HKCU', 'Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings')
        Console.WriteLine('\r\n\r\n=== HKCU Internet Settings ===\r\n')
        if (proxySettings is not null) and (proxySettings.Count != 0):
            for kvp as KeyValuePair[of string, object] in proxySettings:
                Console.WriteLine('  {0,30} : {1}', kvp.Key, kvp.Value)

        proxySettings2 as Dictionary[of string, object] = GetRegValues('HKLM', 'Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings')
        Console.WriteLine('\r\n\r\n=== HKLM Internet Settings ===\r\n')
        if (proxySettings2 is not null) and (proxySettings2.Count != 0):
            for kvp as KeyValuePair[of string, object] in proxySettings2:
                Console.WriteLine('  {0,30} : {1}', kvp.Key, kvp.Value)


    public static def ListLSASettings():
        Console.WriteLine('\r\n\r\n=== LSA Settings ===\r\n')
        settings as Dictionary[of string, object] = GetRegValues('HKLM', 'SYSTEM\\CurrentControlSet\\Control\\Lsa')
        if (settings is not null) and (settings.Count != 0):
            for kvp as KeyValuePair[of string, object] in settings:
                if kvp.Value.GetType().IsArray and (kvp.Value.GetType().GetElementType().ToString() == 'System.String'):
                    result as string = string.Join(',', (kvp.Value cast (string)))
                    Console.WriteLine('  {0,-30} : {1}', kvp.Key, result)

                    if kvp.Key.ToString() == 'Security Packages':
                        r as Regex = Regex('.*wdigest.*')
                        m as Match = r.Match(result)
                        if m.Success:
                            Console.WriteLine('    [*] Wdigest is enabled- plaintext password extraction is possible!')
                else:
                    Console.WriteLine('  {0,-30} : {1}', kvp.Key, kvp.Value)


    public static def ListKerberosTickets():
        if IsHighIntegrity():
            ListKerberosTicketsAllUsers()
        else:
            ListKerberosTicketsCurrentUser()

    public static def ListKerberosTicketsAllUsers():
        // adapted partially from Vincent LE TOUX' work
        //      https://github.com/vletoux/MakeMeEnterpriseAdmin/blob/master/MakeMeEnterpriseAdmin.ps1#L2939-L2950
        // and https://www.dreamincode.net/forums/topic/135033-increment-memory-pointer-issue/
        // also Jared Atkinson's work at https://github.com/Invoke-IR/ACE/blob/master/ACE-Management/PS-ACE/Scripts/ACE_Get-KerberosTicketCache.ps1

        Console.WriteLine('\r\n\r\n=== Kerberos Tickets (All Users) ===\r\n')

        hLsa as IntPtr = LsaRegisterLogonProcessHelper()
        totalTicketCount = 0

        // if the original call fails then it is likely we don't have SeTcbPrivilege
        // to get SeTcbPrivilege we can Impersonate a NT AUTHORITY\SYSTEM Token
        if hLsa == IntPtr.Zero:
            GetSystem()
            // should now have the proper privileges to get a Handle to LSA
            hLsa = LsaRegisterLogonProcessHelper()
            // we don't need our NT AUTHORITY\SYSTEM Token anymore so we can revert to our original token
            RevertToSelf()

        try:
            // first return all the logon sessions

            systime = DateTime(1601, 1, 1, 0, 0, 0, 0)
            //win32 systemdate
            count as UInt64
            luidPtr as IntPtr = IntPtr.Zero
            iter as IntPtr = luidPtr

            ret as uint = LsaEnumerateLogonSessions(count, luidPtr)
            for i in range(0, count):
            // get an array of pointers to LUIDs
                sessionData as IntPtr
                ret = LsaGetLogonSessionData(luidPtr, sessionData)
                data = (Marshal.PtrToStructure(sessionData, typeof(SECURITY_LOGON_SESSION_DATA)) cast SECURITY_LOGON_SESSION_DATA)

                // if we have a valid logon
                if data.PSiD != IntPtr.Zero:
                    // user session data
                    username as string = Marshal.PtrToStringUni(data.Username.Buffer).Trim()
                    sid as System.Security.Principal.SecurityIdentifier = System.Security.Principal.SecurityIdentifier(data.PSiD)
                    domain as string = Marshal.PtrToStringUni(data.LoginDomain.Buffer).Trim()
                    authpackage as string = Marshal.PtrToStringUni(data.AuthenticationPackage.Buffer).Trim()
                    logonType = (data.LogonType cast SECURITY_LOGON_TYPE)
                    logonTime as DateTime = systime.AddTicks((data.LoginTime cast long))
                    logonServer as string = Marshal.PtrToStringUni(data.LogonServer.Buffer).Trim()
                    dnsDomainName as string = Marshal.PtrToStringUni(data.DnsDomainName.Buffer).Trim()
                    upn as string = Marshal.PtrToStringUni(data.Upn.Buffer).Trim()

                    // now we want to get the tickets for this logon ID
                    name = 'kerberos'
                    LSAString as LSA_STRING_IN
                    LSAString.Length = (name.Length cast ushort)
                    LSAString.MaximumLength = ((name.Length + 1) cast ushort)
                    LSAString.Buffer = name

                    ticketPointer as IntPtr = IntPtr.Zero
                    ticketsPointer as IntPtr = IntPtr.Zero
                    sysTime = DateTime(1601, 1, 1, 0, 0, 0, 0)
                    authPack as int
                    returnBufferLength = 0
                    protocalStatus = 0
                    retCode as int

                    tQuery = KERB_QUERY_TKT_CACHE_REQUEST()
                    tickets = KERB_QUERY_TKT_CACHE_RESPONSE()
                    ticket as KERB_TICKET_CACHE_INFO

                    // obtains the unique identifier for the kerberos authentication package.
                    retCode = LsaLookupAuthenticationPackage(hLsa, LSAString, authPack)

                    // input object for querying the ticket cache for a specific logon ID
                    userLogonID = LUID()
                    userLogonID.LowPart = data.LoginID.LowPart
                    userLogonID.HighPart = 0
                    tQuery.LogonId = userLogonID
                    tQuery.MessageType = KERB_PROTOCOL_MESSAGE_TYPE.KerbQueryTicketCacheMessage

                    // query LSA, specifying we want the ticket cache
                    retCode = LsaCallAuthenticationPackage(hLsa, authPack, tQuery, Marshal.SizeOf(tQuery), ticketPointer, returnBufferLength, protocalStatus)

                    Console.WriteLine('\r\n  UserName                 : {0}', username)
                    Console.WriteLine('  Domain                   : {0}', domain)
                    Console.WriteLine('  LogonId                  : {0}', data.LoginID.LowPart)
                    Console.WriteLine('  UserSID                  : {0}', sid.AccountDomainSid)
                    Console.WriteLine('  AuthenticationPackage    : {0}', authpackage)
                    Console.WriteLine('  LogonType                : {0}', logonType)
                    Console.WriteLine('  LogonType                : {0}', logonTime)
                    Console.WriteLine('  LogonServer              : {0}', logonServer)
                    Console.WriteLine('  LogonServerDNSDomain     : {0}', dnsDomainName)
                    Console.WriteLine('  UserPrincipalName        : {0}\r\n', upn)

                    if ticketPointer != IntPtr.Zero:
                        // parse the returned pointer into our initial KERB_QUERY_TKT_CACHE_RESPONSE structure
                        tickets = (Marshal.PtrToStructure((ticketPointer cast System.IntPtr), typeof(KERB_QUERY_TKT_CACHE_RESPONSE)) cast KERB_QUERY_TKT_CACHE_RESPONSE)
                        count2 as int = tickets.CountOfTickets

                        if count2 != 0:
                            Console.WriteLine('    [*] Enumerated {0} ticket(s):\r\n', count2)
                            totalTicketCount += count2
                            // get the size of the structures we're iterating over
                            dataSize as Int32 = Marshal.SizeOf(typeof(KERB_TICKET_CACHE_INFO))
                            for j in range(0, count2):

                                // iterate through the structures
                                currTicketPtr = (((ticketPointer.ToInt64() + ((8 + (j * dataSize)) cast int)) cast long) cast IntPtr)

                                // parse the new ptr to the appropriate structure
                                ticket = (Marshal.PtrToStructure(currTicketPtr, typeof(KERB_TICKET_CACHE_INFO)) cast KERB_TICKET_CACHE_INFO)

                                // extract our fields
                                serverName as string = Marshal.PtrToStringUni(ticket.ServerName.Buffer, (ticket.ServerName.Length / 2))
                                realmName as string = Marshal.PtrToStringUni(ticket.RealmName.Buffer, (ticket.RealmName.Length / 2))
                                startTime as DateTime = DateTime.FromFileTime(ticket.StartTime)
                                endTime as DateTime = DateTime.FromFileTime(ticket.EndTime)
                                renewTime as DateTime = DateTime.FromFileTime(ticket.RenewTime)
                                encryptionType as string = (ticket.EncryptionType cast KERB_ENCRYPTION_TYPE).ToString()
                                ticketFlags as string = (ticket.TicketFlags cast KERB_TICKET_FLAGS).ToString()

                                Console.WriteLine('    ServerName         :  {0}', serverName)
                                Console.WriteLine('    RealmName          :  {0}', realmName)
                                Console.WriteLine('    StartTime          :  {0}', startTime)
                                Console.WriteLine('    EndTime            :  {0}', endTime)
                                Console.WriteLine('    RenewTime          :  {0}', renewTime)
                                Console.WriteLine('    EncryptionType     :  {0}', encryptionType)
                                Console.WriteLine('    TicketFlags        :  {0}\r\n', ticketFlags)
                // move the pointer forward
                luidPtr = (((luidPtr.ToInt64() cast long) + Marshal.SizeOf(typeof(LUID))) cast IntPtr)
                LsaFreeReturnBuffer(sessionData)
            LsaFreeReturnBuffer(luidPtr)

            // disconnect from LSA
            LsaDeregisterLogonProcess(hLsa)

            Console.WriteLine('\r\n\r\n  [*] Enumerated {0} total tickets\r\n', totalTicketCount)
        except ex as Exception:
            Console.WriteLine('  [X] Exception: {0}', ex)

    public static def ListKerberosTicketsCurrentUser():
        // adapted partially from Vincent LE TOUX' work
        //      https://github.com/vletoux/MakeMeEnterpriseAdmin/blob/master/MakeMeEnterpriseAdmin.ps1#L2939-L2950
        // and https://www.dreamincode.net/forums/topic/135033-increment-memory-pointer-issue/
        // also Jared Atkinson's work at https://github.com/Invoke-IR/ACE/blob/master/ACE-Management/PS-ACE/Scripts/ACE_Get-KerberosTicketCache.ps1

        Console.WriteLine('\r\n\r\n=== Kerberos Tickets (Current User) ===\r\n')

        try:
            name = 'kerberos'
            LSAString as LSA_STRING_IN
            LSAString.Length = (name.Length cast ushort)
            LSAString.MaximumLength = ((name.Length + 1) cast ushort)
            LSAString.Buffer = name

            ticketPointer as IntPtr = IntPtr.Zero
            ticketsPointer as IntPtr = IntPtr.Zero
            sysTime = DateTime(1601, 1, 1, 0, 0, 0, 0)
            authPack as int
            returnBufferLength = 0
            protocalStatus = 0
            lsaHandle as IntPtr
            retCode as int

            // If we want to look at tickets from a session other than our own
            // then we need to use LsaRegisterLogonProcess instead of LsaConnectUntrusted
            retCode = LsaConnectUntrusted(lsaHandle)

            tQuery = KERB_QUERY_TKT_CACHE_REQUEST()
            tickets = KERB_QUERY_TKT_CACHE_RESPONSE()
            ticket as KERB_TICKET_CACHE_INFO

            // obtains the unique identifier for the kerberos authentication package.
            retCode = LsaLookupAuthenticationPackage(lsaHandle, LSAString, authPack)

            // input object for querying the ticket cache (https://docs.microsoft.com/en-us/windows/desktop/api/ntsecapi/ns-ntsecapi-_kerb_query_tkt_cache_request)
            tQuery.LogonId = LUID()
            tQuery.MessageType = KERB_PROTOCOL_MESSAGE_TYPE.KerbQueryTicketCacheMessage

            // query LSA, specifying we want the ticket cache
            retCode = LsaCallAuthenticationPackage(lsaHandle, authPack, tQuery, Marshal.SizeOf(tQuery), ticketPointer, returnBufferLength, protocalStatus)

            // parse the returned pointer into our initial KERB_QUERY_TKT_CACHE_RESPONSE structure
            tickets = (Marshal.PtrToStructure((ticketPointer cast System.IntPtr), typeof(KERB_QUERY_TKT_CACHE_RESPONSE)) cast KERB_QUERY_TKT_CACHE_RESPONSE)
            count as int = tickets.CountOfTickets
            Console.WriteLine('  [*] Returned {0} tickets\r\n', count)

            // get the size of the structures we're iterating over
            dataSize as Int32 = Marshal.SizeOf(typeof(KERB_TICKET_CACHE_INFO))
            for i in range(0, count):

                // iterate through the structures
                currTicketPtr = (((ticketPointer.ToInt64() + ((8 + (i * dataSize)) cast int)) cast long) cast IntPtr)

                // parse the new ptr to the appropriate structure
                ticket = (Marshal.PtrToStructure(currTicketPtr, typeof(KERB_TICKET_CACHE_INFO)) cast KERB_TICKET_CACHE_INFO)

                // extract our fields
                serverName as string = Marshal.PtrToStringUni(ticket.ServerName.Buffer, (ticket.ServerName.Length / 2))
                realmName as string = Marshal.PtrToStringUni(ticket.RealmName.Buffer, (ticket.RealmName.Length / 2))
                startTime as DateTime = DateTime.FromFileTime(ticket.StartTime)
                endTime as DateTime = DateTime.FromFileTime(ticket.EndTime)
                renewTime as DateTime = DateTime.FromFileTime(ticket.RenewTime)
                encryptionType as string = (ticket.EncryptionType cast KERB_ENCRYPTION_TYPE).ToString()
                ticketFlags as string = (ticket.TicketFlags cast KERB_TICKET_FLAGS).ToString()

                Console.WriteLine('  ServerName         :  {0}', serverName)
                Console.WriteLine('  RealmName          :  {0}', realmName)
                Console.WriteLine('  StartTime          :  {0}', startTime)
                Console.WriteLine('  EndTime            :  {0}', endTime)
                Console.WriteLine('  RenewTime          :  {0}', renewTime)
                Console.WriteLine('  EncryptionType     :  {0}', encryptionType)
                Console.WriteLine('  TicketFlags        :  {0}\r\n', ticketFlags)

            // disconnect from LSA
            LsaDeregisterLogonProcess(lsaHandle)
        except ex as Exception:
            Console.WriteLine('  [X] Exception: {0}', ex.Message)


    public static def ListKerberosTGTData():
        if IsHighIntegrity():
            ListKerberosTGTDataAllUsers()
        else:
            ListKerberosTGTDataCurrentUser()

    public static def ListKerberosTGTDataAllUsers():
        // adapted partially from Vincent LE TOUX' work
        //      https://github.com/vletoux/MakeMeEnterpriseAdmin/blob/master/MakeMeEnterpriseAdmin.ps1#L2939-L2950
        // and https://www.dreamincode.net/forums/topic/135033-increment-memory-pointer-issue/
        // also Jared Atkinson's work at https://github.com/Invoke-IR/ACE/blob/master/ACE-Management/PS-ACE/Scripts/ACE_Get-KerberosTicketCache.ps1

        Console.WriteLine('\r\n\r\n=== Kerberos TGT Data (All Users) ===\r\n')

        hLsa as IntPtr = LsaRegisterLogonProcessHelper()
        totalTicketCount = 0

        // if the original call fails then it is likely we don't have SeTcbPrivilege
        // to get SeTcbPrivilege we can Impersonate a NT AUTHORITY\SYSTEM Token
        if hLsa == IntPtr.Zero:
            GetSystem()
            // should now have the proper privileges to get a Handle to LSA
            hLsa = LsaRegisterLogonProcessHelper()
            // we don't need our NT AUTHORITY\SYSTEM Token anymore so we can revert to our original token
            RevertToSelf()

        try:
            // first return all the logon sessions

            systime = DateTime(1601, 1, 1, 0, 0, 0, 0)
            //win32 systemdate
            count as UInt64
            luidPtr as IntPtr = IntPtr.Zero
            iter as IntPtr = luidPtr

            ret as uint = LsaEnumerateLogonSessions(count, luidPtr)
            for i in range(0, count):
            // get an array of pointers to LUIDs
                sessionData as IntPtr
                ret = LsaGetLogonSessionData(luidPtr, sessionData)
                data = (Marshal.PtrToStructure(sessionData, typeof(SECURITY_LOGON_SESSION_DATA)) cast SECURITY_LOGON_SESSION_DATA)

                // if we have a valid logon
                if data.PSiD != IntPtr.Zero:
                    // user session data
                    username as string = Marshal.PtrToStringUni(data.Username.Buffer).Trim()
                    sid as System.Security.Principal.SecurityIdentifier = System.Security.Principal.SecurityIdentifier(data.PSiD)
                    domain as string = Marshal.PtrToStringUni(data.LoginDomain.Buffer).Trim()
                    authpackage as string = Marshal.PtrToStringUni(data.AuthenticationPackage.Buffer).Trim()
                    logonType = (data.LogonType cast SECURITY_LOGON_TYPE)
                    logonTime as DateTime = systime.AddTicks((data.LoginTime cast long))
                    logonServer as string = Marshal.PtrToStringUni(data.LogonServer.Buffer).Trim()
                    dnsDomainName as string = Marshal.PtrToStringUni(data.DnsDomainName.Buffer).Trim()
                    upn as string = Marshal.PtrToStringUni(data.Upn.Buffer).Trim()

                    // now we want to get the tickets for this logon ID
                    name = 'kerberos'
                    LSAString as LSA_STRING_IN
                    LSAString.Length = (name.Length cast ushort)
                    LSAString.MaximumLength = ((name.Length + 1) cast ushort)
                    LSAString.Buffer = name

                    responsePointer as IntPtr = IntPtr.Zero
                    authPack as int
                    returnBufferLength = 0
                    protocalStatus = 0
                    retCode as int

                    tQuery = KERB_RETRIEVE_TKT_REQUEST()
                    response = KERB_RETRIEVE_TKT_RESPONSE()

                    // obtains the unique identifier for the kerberos authentication package.
                    retCode = LsaLookupAuthenticationPackage(hLsa, LSAString, authPack)

                    // input object for querying the TGT for a specific logon ID (https://docs.microsoft.com/en-us/windows/desktop/api/ntsecapi/ns-ntsecapi-_kerb_retrieve_tkt_request)
                    userLogonID = LUID()
                    userLogonID.LowPart = data.LoginID.LowPart
                    userLogonID.HighPart = 0
                    tQuery.LogonId = userLogonID
                    tQuery.MessageType = KERB_PROTOCOL_MESSAGE_TYPE.KerbRetrieveTicketMessage
                    // indicate we want kerb creds yo'
                    tQuery.CacheOptions = KERB_CACHE_OPTIONS.KERB_RETRIEVE_TICKET_AS_KERB_CRED

                    // query LSA, specifying we want the the TGT data
                    retCode = LsaCallAuthenticationPackage_KERB_RETRIEVE_TKT(hLsa, authPack, tQuery, Marshal.SizeOf(tQuery), responsePointer, returnBufferLength, protocalStatus)

                    if (retCode == 0) and (responsePointer != IntPtr.Zero):
                        Console.WriteLine('\r\n  UserName                 : {0}', username)
                        Console.WriteLine('  Domain                   : {0}', domain)
                        Console.WriteLine('  LogonId                  : {0}', data.LoginID.LowPart)
                        Console.WriteLine('  UserSID                  : {0}', sid.AccountDomainSid)
                        Console.WriteLine('  AuthenticationPackage    : {0}', authpackage)
                        Console.WriteLine('  LogonType                : {0}', logonType)
                        Console.WriteLine('  LogonType                : {0}', logonTime)
                        Console.WriteLine('  LogonServer              : {0}', logonServer)
                        Console.WriteLine('  LogonServerDNSDomain     : {0}', dnsDomainName)
                        Console.WriteLine('  UserPrincipalName        : {0}', upn)

                        // parse the returned pointer into our initial KERB_RETRIEVE_TKT_RESPONSE structure
                        response = (Marshal.PtrToStructure((responsePointer cast System.IntPtr), typeof(KERB_RETRIEVE_TKT_RESPONSE)) cast KERB_RETRIEVE_TKT_RESPONSE)

                        serviceNameStruct = (Marshal.PtrToStructure(response.Ticket.ServiceName, typeof(KERB_EXTERNAL_NAME)) cast KERB_EXTERNAL_NAME)
                        serviceName as string = Marshal.PtrToStringUni(serviceNameStruct.Names.Buffer, (serviceNameStruct.Names.Length / 2)).Trim()

                        targetName = ''
                        if response.Ticket.TargetName != IntPtr.Zero:
                            targetNameStruct = (Marshal.PtrToStructure(response.Ticket.TargetName, typeof(KERB_EXTERNAL_NAME)) cast KERB_EXTERNAL_NAME)
                            targetName = Marshal.PtrToStringUni(targetNameStruct.Names.Buffer, (targetNameStruct.Names.Length / 2)).Trim()

                        clientNameStruct = (Marshal.PtrToStructure(response.Ticket.ClientName, typeof(KERB_EXTERNAL_NAME)) cast KERB_EXTERNAL_NAME)
                        clientName as string = Marshal.PtrToStringUni(clientNameStruct.Names.Buffer, (clientNameStruct.Names.Length / 2)).Trim()

                        domainName as string = Marshal.PtrToStringUni(response.Ticket.DomainName.Buffer, (response.Ticket.DomainName.Length / 2)).Trim()
                        targetDomainName as string = Marshal.PtrToStringUni(response.Ticket.TargetDomainName.Buffer, (response.Ticket.TargetDomainName.Length / 2)).Trim()
                        altTargetDomainName as string = Marshal.PtrToStringUni(response.Ticket.AltTargetDomainName.Buffer, (response.Ticket.AltTargetDomainName.Length / 2)).Trim()

                        // extract the session key
                        sessionKeyType = (response.Ticket.SessionKey.KeyType cast KERB_ENCRYPTION_TYPE)
                        sessionKeyLength as Int32 = response.Ticket.SessionKey.Length
                        sessionKey as (byte) = array(byte, sessionKeyLength)
                        Marshal.Copy(response.Ticket.SessionKey.Value, sessionKey, 0, sessionKeyLength)
                        base64SessionKey as string = Convert.ToBase64String(sessionKey)

                        keyExpirationTime as DateTime = DateTime.FromFileTime(response.Ticket.KeyExpirationTime)
                        startTime as DateTime = DateTime.FromFileTime(response.Ticket.StartTime)
                        endTime as DateTime = DateTime.FromFileTime(response.Ticket.EndTime)
                        renewUntil as DateTime = DateTime.FromFileTime(response.Ticket.RenewUntil)
                        timeSkew as Int64 = response.Ticket.TimeSkew
                        encodedTicketSize as Int32 = response.Ticket.EncodedTicketSize

                        ticketFlags as string = (response.Ticket.TicketFlags cast KERB_TICKET_FLAGS).ToString()

                        // extract the TGT and base64 encode it
                        encodedTicket as (byte) = array(byte, encodedTicketSize)
                        Marshal.Copy(response.Ticket.EncodedTicket, encodedTicket, 0, encodedTicketSize)
                        base64TGT as string = Convert.ToBase64String(encodedTicket)

                        Console.WriteLine('  ServiceName              : {0}', serviceName)
                        Console.WriteLine('  TargetName               : {0}', targetName)
                        Console.WriteLine('  ClientName               : {0}', clientName)
                        Console.WriteLine('  DomainName               : {0}', domainName)
                        Console.WriteLine('  TargetDomainName         : {0}', targetDomainName)
                        Console.WriteLine('  AltTargetDomainName      : {0}', altTargetDomainName)
                        Console.WriteLine('  SessionKeyType           : {0}', sessionKeyType)
                        Console.WriteLine('  Base64SessionKey         : {0}', base64SessionKey)
                        Console.WriteLine('  KeyExpirationTime        : {0}', keyExpirationTime)
                        Console.WriteLine('  TicketFlags              : {0}', ticketFlags)
                        Console.WriteLine('  StartTime                : {0}', startTime)
                        Console.WriteLine('  EndTime                  : {0}', endTime)
                        Console.WriteLine('  RenewUntil               : {0}', renewUntil)
                        Console.WriteLine('  TimeSkew                 : {0}', timeSkew)
                        Console.WriteLine('  EncodedTicketSize        : {0}', encodedTicketSize)
                        Console.WriteLine('  Base64EncodedTicket      :\r\n')
                        // display the TGT, columns of 100 chararacters
                        for line as string in Split(base64TGT, 100):
                            Console.WriteLine('    {0}', line)
                        Console.WriteLine()
                        totalTicketCount += 1
                luidPtr = (((luidPtr.ToInt64() cast long) + Marshal.SizeOf(typeof(LUID))) cast IntPtr)
                //move the pointer forward
                LsaFreeReturnBuffer(sessionData)
            //free the SECURITY_LOGON_SESSION_DATA memory in the struct
            LsaFreeReturnBuffer(luidPtr)
            //free the array of LUIDs
            // disconnect from LSA
            LsaDeregisterLogonProcess(hLsa)

            Console.WriteLine('\r\n\r\n  [*] Extracted {0} total tickets\r\n', totalTicketCount)
        except ex as Exception:
            Console.WriteLine('  [X] Exception: {0}', ex)

    public static def ListKerberosTGTDataCurrentUser():
        // adapted partially from Vincent LE TOUX' work
        //      https://github.com/vletoux/MakeMeEnterpriseAdmin/blob/master/MakeMeEnterpriseAdmin.ps1#L2939-L2950
        // and https://www.dreamincode.net/forums/topic/135033-increment-memory-pointer-issue/
        // also Jared Atkinson's work at https://github.com/Invoke-IR/ACE/blob/master/ACE-Management/PS-ACE/Scripts/ACE_Get-KerberosTicketCache.ps1

        Console.WriteLine('\r\n\r\n=== Kerberos TGT Data (Current User) ===\r\n')

        try:
            name = 'kerberos'
            LSAString as LSA_STRING_IN
            LSAString.Length = (name.Length cast ushort)
            LSAString.MaximumLength = ((name.Length + 1) cast ushort)
            LSAString.Buffer = name

            responsePointer as IntPtr = IntPtr.Zero
            authPack as int
            returnBufferLength = 0
            protocalStatus = 0
            lsaHandle as IntPtr
            retCode as int

            // If we want to look at tickets from a session other than our own
            // then we need to use LsaRegisterLogonProcess instead of LsaConnectUntrusted
            retCode = LsaConnectUntrusted(lsaHandle)

            tQuery = KERB_RETRIEVE_TKT_REQUEST()
            response = KERB_RETRIEVE_TKT_RESPONSE()

            // obtains the unique identifier for the kerberos authentication package.
            retCode = LsaLookupAuthenticationPackage(lsaHandle, LSAString, authPack)

            // input object for querying the TGT (https://docs.microsoft.com/en-us/windows/desktop/api/ntsecapi/ns-ntsecapi-_kerb_retrieve_tkt_request)
            tQuery.LogonId = LUID()
            tQuery.MessageType = KERB_PROTOCOL_MESSAGE_TYPE.KerbRetrieveTicketMessage
            // indicate we want kerb creds yo'
            //tQuery.CacheOptions = KERB_CACHE_OPTIONS.KERB_RETRIEVE_TICKET_AS_KERB_CRED;

            // query LSA, specifying we want the the TGT data
            retCode = LsaCallAuthenticationPackage_KERB_RETRIEVE_TKT(lsaHandle, authPack, tQuery, Marshal.SizeOf(tQuery), responsePointer, returnBufferLength, protocalStatus)

            // parse the returned pointer into our initial KERB_RETRIEVE_TKT_RESPONSE structure
            response = (Marshal.PtrToStructure((responsePointer cast System.IntPtr), typeof(KERB_RETRIEVE_TKT_RESPONSE)) cast KERB_RETRIEVE_TKT_RESPONSE)

            serviceNameStruct = (Marshal.PtrToStructure(response.Ticket.ServiceName, typeof(KERB_EXTERNAL_NAME)) cast KERB_EXTERNAL_NAME)
            serviceName as string = Marshal.PtrToStringUni(serviceNameStruct.Names.Buffer, (serviceNameStruct.Names.Length / 2)).Trim()

            targetName = ''
            if response.Ticket.TargetName != IntPtr.Zero:
                targetNameStruct = (Marshal.PtrToStructure(response.Ticket.TargetName, typeof(KERB_EXTERNAL_NAME)) cast KERB_EXTERNAL_NAME)
                targetName = Marshal.PtrToStringUni(targetNameStruct.Names.Buffer, (targetNameStruct.Names.Length / 2)).Trim()

            clientNameStruct = (Marshal.PtrToStructure(response.Ticket.ClientName, typeof(KERB_EXTERNAL_NAME)) cast KERB_EXTERNAL_NAME)
            clientName as string = Marshal.PtrToStringUni(clientNameStruct.Names.Buffer, (clientNameStruct.Names.Length / 2)).Trim()

            domainName as string = Marshal.PtrToStringUni(response.Ticket.DomainName.Buffer, (response.Ticket.DomainName.Length / 2)).Trim()
            targetDomainName as string = Marshal.PtrToStringUni(response.Ticket.TargetDomainName.Buffer, (response.Ticket.TargetDomainName.Length / 2)).Trim()
            altTargetDomainName as string = Marshal.PtrToStringUni(response.Ticket.AltTargetDomainName.Buffer, (response.Ticket.AltTargetDomainName.Length / 2)).Trim()

            // extract the session key
            sessionKeyType = (response.Ticket.SessionKey.KeyType cast KERB_ENCRYPTION_TYPE)
            sessionKeyLength as Int32 = response.Ticket.SessionKey.Length
            sessionKey as (byte) = array(byte, sessionKeyLength)
            Marshal.Copy(response.Ticket.SessionKey.Value, sessionKey, 0, sessionKeyLength)
            base64SessionKey as string = Convert.ToBase64String(sessionKey)

            keyExpirationTime as DateTime = DateTime.FromFileTime(response.Ticket.KeyExpirationTime)
            startTime as DateTime = DateTime.FromFileTime(response.Ticket.StartTime)
            endTime as DateTime = DateTime.FromFileTime(response.Ticket.EndTime)
            renewUntil as DateTime = DateTime.FromFileTime(response.Ticket.RenewUntil)
            timeSkew as Int64 = response.Ticket.TimeSkew
            encodedTicketSize as Int32 = response.Ticket.EncodedTicketSize

            ticketFlags as string = (response.Ticket.TicketFlags cast KERB_TICKET_FLAGS).ToString()

            // extract the TGT and base64 encode it
            encodedTicket as (byte) = array(byte, encodedTicketSize)
            Marshal.Copy(response.Ticket.EncodedTicket, encodedTicket, 0, encodedTicketSize)
            base64TGT as string = Convert.ToBase64String(encodedTicket)

            Console.WriteLine('  ServiceName              : {0}', serviceName)
            Console.WriteLine('  TargetName               : {0}', targetName)
            Console.WriteLine('  ClientName               : {0}', clientName)
            Console.WriteLine('  DomainName               : {0}', domainName)
            Console.WriteLine('  TargetDomainName         : {0}', targetDomainName)
            Console.WriteLine('  AltTargetDomainName      : {0}', altTargetDomainName)
            Console.WriteLine('  SessionKeyType           : {0}', sessionKeyType)
            Console.WriteLine('  Base64SessionKey         : {0}', base64SessionKey)
            Console.WriteLine('  KeyExpirationTime        : {0}', keyExpirationTime)
            Console.WriteLine('  TicketFlags              : {0}', ticketFlags)
            Console.WriteLine('  StartTime                : {0}', startTime)
            Console.WriteLine('  EndTime                  : {0}', endTime)
            Console.WriteLine('  RenewUntil               : {0}', renewUntil)
            Console.WriteLine('  TimeSkew                 : {0}', timeSkew)
            Console.WriteLine('  EncodedTicketSize        : {0}', encodedTicketSize)
            Console.WriteLine('  Base64EncodedTicket      :\r\n')
            // display the TGT, columns of 100 chararacters
            for line as string in Split(base64TGT, 100):
                Console.WriteLine('    {0}', line)
            Console.WriteLine()

            // disconnect from LSA
            LsaDeregisterLogonProcess(lsaHandle)
        except ex as Exception:
            Console.WriteLine('  [X] Exception: {0}', ex.Message)


    // https://github.com/pauldotknopf/WindowsSDK7-Samples/blob/master/security/authorization/klist/KList.c#L585
    // currently not working :(
    //public static void ListKerberosTicketDataCurrentUser()
    //{
    //    // adapted partially from Vincent LE TOUX' work
    //    //      https://github.com/vletoux/MakeMeEnterpriseAdmin/blob/master/MakeMeEnterpriseAdmin.ps1#L2939-L2950
    //    // and https://www.dreamincode.net/forums/topic/135033-increment-memory-pointer-issue/
    //    // also Jared Atkinson's work at https://github.com/Invoke-IR/ACE/blob/master/ACE-Management/PS-ACE/Scripts/ACE_Get-KerberosTicketCache.ps1

    //    Console.WriteLine("\r\n\r\n=== Kerberos Ticket Data (Current User) ===\r\n");

    //    //try
    //    //{
    //    string name = "kerberos";
    //    LSA_STRING_IN LSAString;
    //    LSAString.Length = (ushort)name.Length;
    //    LSAString.MaximumLength = (ushort)(name.Length + 1);
    //    LSAString.Buffer = name;

    //    IntPtr ticketPointer = IntPtr.Zero;
    //    IntPtr ticketsPointer = IntPtr.Zero;
    //    int authPack;
    //    int returnBufferLength = 0;
    //    int protocalStatus = 0;
    //    IntPtr lsaHandle;
    //    int retCode;

    //    // If we want to look at tickets from a session other than our own
    //    // then we need to use LsaRegisterLogonProcess instead of LsaConnectUntrusted
    //    retCode = LsaConnectUntrusted(out lsaHandle);

    //    // obtains the unique identifier for the kerberos authentication package.
    //    retCode = LsaLookupAuthenticationPackage(lsaHandle, ref LSAString, out authPack);

    //    UNICODE_STRING targetName = new UNICODE_STRING("krbtgt/TESTLAB.LOCAL");
    //    UNICODE_STRING target = new UNICODE_STRING();

    //    KERB_RETRIEVE_TKT_RESPONSE CacheResponse = new KERB_RETRIEVE_TKT_RESPONSE();

    //    // LMEM_ZEROINIT -> 0x0040
    //    IntPtr temp = LocalAlloc(0x0040, (uint)(targetName.Length + Marshal.SizeOf(typeof(KERB_RETRIEVE_TKT_REQUEST))));

    //    IntPtr unmanagedAddr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(KERB_RETRIEVE_TKT_REQUEST)));
    //    //Marshal.StructureToPtr(managedObj, unmanagedAddr, true);
    //    KERB_RETRIEVE_TKT_REQUEST_UNI CacheRequest = (KERB_RETRIEVE_TKT_REQUEST_UNI)Marshal.PtrToStructure(temp, typeof(KERB_RETRIEVE_TKT_REQUEST_UNI));
    //    CacheRequest.MessageType = KERB_PROTOCOL_MESSAGE_TYPE.KerbRetrieveEncodedTicketMessage;

    //    // KERB_RETRIEVE_TKT_REQUEST_UNI
    //    IntPtr CacheRequestPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(KERB_RETRIEVE_TKT_REQUEST)));
    //    Marshal.StructureToPtr(CacheRequest, CacheRequestPtr, false);
    //    target.buffer = (IntPtr)(CacheRequestPtr.ToInt64() + 1);
    //    target.Length = targetName.Length;
    //    target.MaximumLength = targetName.MaximumLength;

    //    CopyMemory(target.buffer, targetName.buffer, targetName.Length);

    //    CacheRequest.TargetName = target;

    //    IntPtr responsePointer = IntPtr.Zero;
    //    int returnBufferLength2 = 0;
    //    // query LSA, specifying we want the the specified ticket data
    //    retCode = LsaCallAuthenticationPackage_KERB_RETRIEVE_TKT_UNI(lsaHandle, authPack, ref CacheRequest, Marshal.SizeOf(CacheRequest) + targetName.Length, out responsePointer, out returnBufferLength2, out protocalStatus);
    //    Console.WriteLine("LsaCallAuthenticationPackage_KERB_RETRIEVE_TKT_UNI retCode: {0}", retCode);
    //    Console.WriteLine("returnBufferLength: {0}", returnBufferLength2);
    //    Console.WriteLine("responsePointer: {0}\r\n", responsePointer);
    //    Console.WriteLine("protocalStatus: {0}\r\n", (uint)protocalStatus);
    //    Console.Out.Flush();


    //    //string clientName = Marshal.PtrToStringUni(CacheResponse.Ticket.ClientName, CacheResponse.Ticket.ClientName.L / 2);
    //    DateTime startTime = DateTime.FromFileTime(CacheResponse.Ticket.StartTime);
    //    DateTime endTime = DateTime.FromFileTime(CacheResponse.Ticket.EndTime);
    //    Console.WriteLine("startTime: {0}", startTime);
    //    Console.WriteLine("endTime: {0}", endTime);

    //    //// query LSA, specifying we want the ticket cache
    //    //retCode = LsaCallAuthenticationPackage(lsaHandle, authPack, ref tQuery, Marshal.SizeOf(tQuery), out ticketPointer, out returnBufferLength, out protocalStatus);

    //    //// parse the returned pointer into our initial KERB_QUERY_TKT_CACHE_RESPONSE structure
    //    //tickets = (KERB_QUERY_TKT_CACHE_EX_RESPONSE)Marshal.PtrToStructure((System.IntPtr)ticketPointer, typeof(KERB_QUERY_TKT_CACHE_EX_RESPONSE));
    //    //int count = tickets.CountOfTickets;
    //    //Console.WriteLine("  [*] Returned {0} tickets\r\n", count);

    //    //// get the size of the structures we're iterating over
    //    //Int32 dataSize = Marshal.SizeOf(typeof(KERB_TICKET_CACHE_INFO_EX));

    //    //for (int i = 0; i < count; i++)
    //    //{
    //    //    // iterate through the structures
    //    //    IntPtr currTicketPtr = (IntPtr)(long)((ticketPointer.ToInt64() + (int)(8 + i * dataSize)));

    //    //    // parse the new ptr to the appropriate structure
    //    //    ticket = (KERB_TICKET_CACHE_INFO_EX)Marshal.PtrToStructure(currTicketPtr, typeof(KERB_TICKET_CACHE_INFO_EX));

    //    //    // extract our fields
    //    //    string clientName = Marshal.PtrToStringUni(ticket.ClientName.Buffer, ticket.ClientName.Length / 2);
    //    //    string clientRealm = Marshal.PtrToStringUni(ticket.ClientRealm.Buffer, ticket.ClientRealm.Length / 2);
    //    //    string serverName = Marshal.PtrToStringUni(ticket.ServerName.Buffer, ticket.ServerName.Length / 2);
    //    //    string serverRealm = Marshal.PtrToStringUni(ticket.ServerRealm.Buffer, ticket.ServerRealm.Length / 2);
    //    //    Console.WriteLine("clientName: {0}", clientName);
    //    //    Console.WriteLine("clientRealm: {0}", clientRealm);
    //    //    Console.WriteLine("serverName: {0}", serverName);
    //    //    Console.WriteLine("serverRealm: {0}", serverRealm);
    //    //    DateTime startTime = DateTime.FromFileTime(ticket.StartTime);
    //    //    DateTime endTime = DateTime.FromFileTime(ticket.EndTime);
    //    //    DateTime renewTime = DateTime.FromFileTime(ticket.RenewTime);
    //    //    string encryptionType = ((KERB_ENCRYPTION_TYPE)ticket.EncryptionType).ToString();
    //    //    string ticketFlags = ((KERB_TICKET_FLAGS)ticket.TicketFlags).ToString();

    //    //KERB_RETRIEVE_TKT_REQUEST ticketQuery = new KERB_RETRIEVE_TKT_REQUEST();
    //    //KERB_RETRIEVE_TKT_RESPONSE response = new KERB_RETRIEVE_TKT_RESPONSE();

    //    //// input object for querying the ticket cache
    //    ////ticketQuery.LogonId = new LUID();
    //    //ticketQuery.MessageType = KERB_PROTOCOL_MESSAGE_TYPE.KerbRetrieveEncodedTicketMessage;
    //    //// indicate we want kerb creds yo'
    //    //ticketQuery.CacheOptions = KERB_CACHE_OPTIONS.KERB_RETRIEVE_TICKET_AS_KERB_CRED;
    //    //ticketQuery.TicketFlags = ticket.TicketFlags;
    //    ////ticketQuery.TargetName = ticket.ServerName;

    //    //string targetName2 = "krbtgt/TESTLAB.LOCAL";
    //    //LSA_STRING_IN LSAString2;
    //    //LSAString2.Length = (ushort)targetName2.Length;
    //    //LSAString2.MaximumLength = (ushort)(targetName2.Length + 1);
    //    //LSAString2.Buffer = targetName2;
    //    //ticketQuery.TargetName = LSAString2;

    //    //Console.WriteLine("flags: {0}\r\n", ticket.TicketFlags.ToString("X2"));

    //    //IntPtr responsePointer = IntPtr.Zero;
    //    //int returnBufferLength2 = 0;
    //    //// query LSA, specifying we want the the specified ticket data
    //    //retCode = LsaCallAuthenticationPackage_KERB_RETRIEVE_TKT(lsaHandle, authPack, ref ticketQuery, Marshal.SizeOf(ticketQuery), out responsePointer, out returnBufferLength2, out protocalStatus);
    //    //Console.WriteLine("LsaCallAuthenticationPackage_KERB_RETRIEVE_TKT retCode: {0}", retCode);
    //    //Console.WriteLine("returnBufferLength: {0}", returnBufferLength2);
    //    //Console.WriteLine("responsePointer: {0}\r\n", responsePointer);
    //    //// parse the returned pointer into our initial KERB_RETRIEVE_TKT_RESPONSE structure

    //    //response = (KERB_RETRIEVE_TKT_RESPONSE)Marshal.PtrToStructure((System.IntPtr)responsePointer, typeof(KERB_RETRIEVE_TKT_RESPONSE));

    //    //KERB_EXTERNAL_NAME serviceNameStruct = (KERB_EXTERNAL_NAME)Marshal.PtrToStructure(response.Ticket.ServiceName, typeof(KERB_EXTERNAL_NAME));
    //    //string serviceName = Marshal.PtrToStringUni(serviceNameStruct.Names.Buffer, serviceNameStruct.Names.Length / 2).Trim();

    //    //string targetName = "";
    //    //if (response.Ticket.TargetName != IntPtr.Zero)
    //    //{
    //    //    KERB_EXTERNAL_NAME targetNameStruct = (KERB_EXTERNAL_NAME)Marshal.PtrToStructure(response.Ticket.TargetName, typeof(KERB_EXTERNAL_NAME));
    //    //    targetName = Marshal.PtrToStringUni(targetNameStruct.Names.Buffer, targetNameStruct.Names.Length / 2).Trim();
    //    //}

    //    //KERB_EXTERNAL_NAME clientNameStruct = (KERB_EXTERNAL_NAME)Marshal.PtrToStructure(response.Ticket.ClientName, typeof(KERB_EXTERNAL_NAME));
    //    ////string clientName = Marshal.PtrToStringUni(clientNameStruct.Names.Buffer, clientNameStruct.Names.Length / 2).Trim();

    //    //string domainName = Marshal.PtrToStringUni(response.Ticket.DomainName.Buffer, response.Ticket.DomainName.Length / 2).Trim();
    //    //string targetDomainName = Marshal.PtrToStringUni(response.Ticket.TargetDomainName.Buffer, response.Ticket.TargetDomainName.Length / 2).Trim();
    //    //string altTargetDomainName = Marshal.PtrToStringUni(response.Ticket.AltTargetDomainName.Buffer, response.Ticket.AltTargetDomainName.Length / 2).Trim();

    //    //// extract the session key
    //    //KERB_ENCRYPTION_TYPE sessionKeyType = (KERB_ENCRYPTION_TYPE)response.Ticket.SessionKey.KeyType;
    //    //Int32 sessionKeyLength = response.Ticket.SessionKey.Length;
    //    //byte[] sessionKey = new byte[sessionKeyLength];
    //    //Marshal.Copy(response.Ticket.SessionKey.Value, sessionKey, 0, sessionKeyLength);
    //    //string base64SessionKey = Convert.ToBase64String(sessionKey);

    //    //DateTime keyExpirationTime = DateTime.FromFileTime(response.Ticket.KeyExpirationTime);
    //    //DateTime startTime2 = DateTime.FromFileTime(response.Ticket.StartTime);
    //    //DateTime endTime2 = DateTime.FromFileTime(response.Ticket.EndTime);
    //    //DateTime renewUntil = DateTime.FromFileTime(response.Ticket.RenewUntil);
    //    //Int64 timeSkew = response.Ticket.TimeSkew;
    //    //Int32 encodedTicketSize = response.Ticket.EncodedTicketSize;

    //    //string ticketFlags2 = ((KERB_TICKET_FLAGS)response.Ticket.TicketFlags).ToString();

    //    //// extract the ticket and base64 encode it
    //    //byte[] encodedTicket = new byte[encodedTicketSize];
    //    //Marshal.Copy(response.Ticket.EncodedTicket, encodedTicket, 0, encodedTicketSize);
    //    //string base64Ticket = Convert.ToBase64String(encodedTicket);

    //    //Console.WriteLine("  ServiceName              : {0}", serviceName);
    //    //Console.WriteLine("  TargetName               : {0}", targetName);
    //    //Console.WriteLine("  ClientName               : {0}", clientName);
    //    //Console.WriteLine("  DomainName               : {0}", domainName);
    //    //Console.WriteLine("  TargetDomainName         : {0}", targetDomainName);
    //    //Console.WriteLine("  AltTargetDomainName      : {0}", altTargetDomainName);
    //    //Console.WriteLine("  SessionKeyType           : {0}", sessionKeyType);
    //    //Console.WriteLine("  Base64SessionKey         : {0}", base64SessionKey);
    //    //Console.WriteLine("  KeyExpirationTime        : {0}", keyExpirationTime);
    //    //Console.WriteLine("  TicketFlags              : {0}", ticketFlags2);
    //    //Console.WriteLine("  StartTime                : {0}", startTime2);
    //    //Console.WriteLine("  EndTime                  : {0}", endTime2);
    //    //Console.WriteLine("  RenewUntil               : {0}", renewUntil);
    //    //Console.WriteLine("  EncodedTicketSize        : {0}", encodedTicketSize);
    //    //Console.WriteLine("  Base64EncodedTicket      :\r\n");
    //    //// display the TGT, columns of 80 chararacters
    //    //foreach (string line in Split(base64Ticket, 80))
    //    //{
    //    //    Console.WriteLine("    {0}", line);
    //    //}
    //    //Console.WriteLine();
    //    //}

    //    // disconnect from LSA
    //    LsaDeregisterLogonProcess(lsaHandle);
    //    //}
    //    //catch (Exception ex)
    //    //{
    //    //    Console.WriteLine("  [X] Exception: {0}", ex.Message);
    //    //}
    //}


    public static def ListLogonSessions():
        // https://www.pinvoke.net/default.aspx/secur32.lsalogonuser
        // list user logons combined with logon session data via WMI
        domain as string
        if not IsHighIntegrity():
            userDomainRegex = Regex('Domain="(.*)",Name="(.*)"')
            logonIdRegex = Regex('LogonId="(\\d+)"')
            Console.WriteLine('\r\n\r\n=== Logon Sessions (via WMI) ===\r\n\r\n')
            logonMap as Dictionary[of string, (string)] = Dictionary[of string, (string)]()
            try:
                wmiData = ManagementObjectSearcher('root\\cimv2', 'SELECT * FROM Win32_LoggedOnUser')
                data as ManagementObjectCollection = wmiData.Get()
                for result as ManagementObject in data:
                    m as Match = logonIdRegex.Match(result['Dependent'].ToString())
                    if m.Success:
                        logonId as string = m.Groups[1].ToString()
                        m2 as Match = userDomainRegex.Match(result['Antecedent'].ToString())
                        if m2.Success:
                            domain = m2.Groups[1].ToString()
                            user as string = m2.Groups[2].ToString()
                            logonMap.Add(logonId, (of string: domain, user))

                wmiData2 = ManagementObjectSearcher('root\\cimv2', 'SELECT * FROM Win32_LogonSession')
                data2 as ManagementObjectCollection = wmiData2.Get()

                for result2 as ManagementObject in data2:
                    userDomain as (string) = logonMap[result2['LogonId'].ToString()]
                    domain = userDomain[0]
                    userName as string = userDomain[1]
                    startTime as date = System.Management.ManagementDateTimeConverter.ToDateTime(result2['StartTime'].ToString())

                    logonType as string = String.Format('{0}', (Int32.Parse(result2['LogonType'].ToString()) cast SECURITY_LOGON_TYPE))

                    Console.WriteLine('  UserName                 : {0}', userName)
                    Console.WriteLine('  Domain                   : {0}', domain)
                    Console.WriteLine('  LogonId                  : {0}', result2['LogonId'].ToString())
                    Console.WriteLine('  LogonType                : {0}', logonType)
                    Console.WriteLine('  AuthenticationPackage    : {0}', result2['AuthenticationPackage'].ToString())
                    Console.WriteLine('  StartTime                : {0}\r\n', startTime)
            except ex as Exception:
                Console.WriteLine('  [X] Exception: {0}', ex.Message)
        else:
            // heavily adapted from from Jared Hill:
            //      https://www.codeproject.com/Articles/18179/Using-the-Local-Security-Authority-to-Enumerate-Us

            Console.WriteLine('\r\n\r\n=== Logon Sessions (via LSA) ===\r\n\r\n')

            try:
                systime = DateTime(1601, 1, 1, 0, 0, 0, 0)
                //win32 systemdate
                count as UInt64
                luidPtr as IntPtr = IntPtr.Zero
                iter as IntPtr = luidPtr

                ret as uint = LsaEnumerateLogonSessions(count, luidPtr)
                for i in range(0, count):
                // get an array of pointers to LUIDs
                    sessionData as IntPtr

                    ret = LsaGetLogonSessionData(luidPtr, sessionData)
                    data__2 = (Marshal.PtrToStructure(sessionData, typeof(SECURITY_LOGON_SESSION_DATA)) cast SECURITY_LOGON_SESSION_DATA)

                    // if we have a valid logon
                    if data__2.PSiD != IntPtr.Zero:
                        // get the account username
                        username as string = Marshal.PtrToStringUni(data__2.Username.Buffer).Trim()

                        // convert the security identifier of the user
                        sid as System.Security.Principal.SecurityIdentifier = System.Security.Principal.SecurityIdentifier(data__2.PSiD)

                        // domain for this account
                        domain = Marshal.PtrToStringUni(data__2.LoginDomain.Buffer).Trim()

                        // authentication package
                        authpackage as string = Marshal.PtrToStringUni(data__2.AuthenticationPackage.Buffer).Trim()

                        // logon type
                        logonType__2 = (data__2.LogonType cast SECURITY_LOGON_TYPE)

                        // datetime the session was logged in
                        logonTime as DateTime = systime.AddTicks((data__2.LoginTime cast long))

                        // user's logon server
                        logonServer as string = Marshal.PtrToStringUni(data__2.LogonServer.Buffer).Trim()

                        // logon server's DNS domain
                        dnsDomainName as string = Marshal.PtrToStringUni(data__2.DnsDomainName.Buffer).Trim()

                        // user principalname
                        upn as string = Marshal.PtrToStringUni(data__2.Upn.Buffer).Trim()

                        Console.WriteLine('  UserName                 : {0}', username)
                        Console.WriteLine('  Domain                   : {0}', domain)
                        Console.WriteLine('  LogonId                  : {0}', data__2.LoginID.LowPart)
                        Console.WriteLine('  UserSID                  : {0}', sid.AccountDomainSid)
                        Console.WriteLine('  AuthenticationPackage    : {0}', authpackage)
                        Console.WriteLine('  LogonType                : {0}', logonType__2)
                        Console.WriteLine('  LogonType                : {0}', logonTime)
                        Console.WriteLine('  LogonServer              : {0}', logonServer)
                        Console.WriteLine('  LogonServerDNSDomain     : {0}', dnsDomainName)
                        Console.WriteLine('  UserPrincipalName        : {0}\r\n', upn)
                    // move the pointer forward
                    luidPtr = (((luidPtr.ToInt64() cast long) + Marshal.SizeOf(typeof(LUID))) cast IntPtr)
                    LsaFreeReturnBuffer(sessionData)
                LsaFreeReturnBuffer(luidPtr)
            except ex as Exception:
                Console.WriteLine('  [X] Exception: {0}', ex)


    public static def ListAuditSettings():
        Console.WriteLine('\r\n\r\n=== Audit Settings ===\r\n')
        settings as Dictionary[of string, object] = GetRegValues('HKLM', 'Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit')
        if (settings is not null) and (settings.Count != 0):
            for kvp as KeyValuePair[of string, object] in settings:
                if kvp.Value.GetType().IsArray and (kvp.Value.GetType().GetElementType().ToString() == 'System.String'):
                    result as string = string.Join(',', (kvp.Value cast (string)))
                    Console.WriteLine('  {0,-30} : {1}', kvp.Key, result)
                else:
                    Console.WriteLine('  {0,-30} : {1}', kvp.Key, kvp.Value)


    public static def ListWEFSettings():
        Console.WriteLine('\r\n\r\n=== WEF Settings ===\r\n')
        settings as Dictionary[of string, object] = GetRegValues('HKLM', 'Software\\Policies\\Microsoft\\Windows\\EventLog\\EventForwarding\\SubscriptionManager')
        if (settings is not null) and (settings.Count != 0):
            for kvp as KeyValuePair[of string, object] in settings:
                if kvp.Value.GetType().IsArray and (kvp.Value.GetType().GetElementType().ToString() == 'System.String'):
                    result as string = string.Join(',', (kvp.Value cast (string)))
                    Console.WriteLine('  {0,-30} : {1}', kvp.Key, result)
                else:
                    Console.WriteLine('  {0,-30} : {1}', kvp.Key, kvp.Value)


    public static def ListLapsSettings():
        Console.WriteLine('\r\n\r\n=== LAPS Settings ===\r\n')

        AdmPwdEnabled as string = GetRegValue('HKLM', 'Software\\Policies\\Microsoft Services\\AdmPwd', 'AdmPwdEnabled')

        if AdmPwdEnabled != '':
            Console.WriteLine('  {0,-37} : {1}', 'LAPS Enabled', AdmPwdEnabled)

            LAPSAdminAccountName as string = GetRegValue('HKLM', 'Software\\Policies\\Microsoft Services\\AdmPwd', 'AdminAccountName')
            Console.WriteLine('  {0,-37} : {1}', 'LAPS Admin Account Name', LAPSAdminAccountName)

            LAPSPasswordComplexity as string = GetRegValue('HKLM', 'Software\\Policies\\Microsoft Services\\AdmPwd', 'PasswordComplexity')
            Console.WriteLine('  {0,-37} : {1}', 'LAPS Password Complexity', LAPSPasswordComplexity)

            LAPSPasswordLength as string = GetRegValue('HKLM', 'Software\\Policies\\Microsoft Services\\AdmPwd', 'PasswordLength')
            Console.WriteLine('  {0,-37} : {1}', 'LAPS Password Length', LAPSPasswordLength)

            LASPwdExpirationProtectionEnabled as string = GetRegValue('HKLM', 'Software\\Policies\\Microsoft Services\\AdmPwd', 'PwdExpirationProtectionEnabled')
            Console.WriteLine('  {0,-37} : {1}', 'LAPS Expiration Protection Enabled', LASPwdExpirationProtectionEnabled)
        else:
            Console.WriteLine('  [*] LAPS not installed')


    public static def ListLocalGroupMembers():
        // adapted from https://stackoverflow.com/questions/33935825/pinvoke-netlocalgroupgetmembers-runs-into-fatalexecutionengineerror/33939889#33939889

        try:
            Console.WriteLine('\r\n\r\n=== Local Group Memberships ===\r\n')

            // localization for @cnotin ;)
            groupsSIDs as (string) = ('S-1-5-32-544', 'S-1-5-32-555', 'S-1-5-32-562', 'S-1-5-32-580')
            // Administrators
            // RDP
            // COM
            // Remote Management

            for sid as string in groupsSIDs:
                groupNameFull as string = TranslateSid(sid)
                if string.IsNullOrEmpty(groupNameFull):
                    // e.g. "S-1-5-32-580" for "Remote Management Users" can be missing on older versions of Windows
                    Console.WriteLine('  [X] Cannot find SID translation for \'{0}\'', sid)
                    continue

                groupName as string = groupNameFull.Substring((groupNameFull.IndexOf(char('\\')) + 1))
                Console.WriteLine('  * {0} *\r\n', groupName)
                members as (string) = GetLocalGroupMembers(groupName)
                if members is not null:
                    for member as string in members:
                        Console.WriteLine('    {0}', member)

                Console.WriteLine('')
        except ex as Exception:
            Console.WriteLine('  [X] Exception: {0}', ex.Message)


    public static def ListMappedDrives():
        try:
            Console.WriteLine('\r\n\r\n=== Drive Information (via .NET) ===\r\n')

            // grab all drive letters
            driveInfos as (DriveInfo) = DriveInfo.GetDrives()

            Console.WriteLine('  {0,-10}   {1}', 'Drive', 'Mapped Location')

            for driveInfo as DriveInfo in driveInfos:
                // try to resolve each drive to a UNC mapped location
                path as string = GetUNCPath(driveInfo.Name)

                Console.WriteLine('  {0,-10} : {1}', driveInfo.Name, path)
        except ex as Exception:
            Console.WriteLine('  [X] Exception: {0}', ex.Message)


    public static def ListWMIMappedDrives():
        try:
            wmiData = ManagementObjectSearcher('root\\cimv2', 'SELECT * FROM win32_networkconnection')
            data as ManagementObjectCollection = wmiData.Get()

            Console.WriteLine('\r\n\r\n=== Mapped Drives (via WMI) ===\r\n')

            for result as ManagementObject in data:
                Console.WriteLine('  LocalName        : {0}', result['LocalName'])
                Console.WriteLine('  RemoteName       : {0}', result['RemoteName'])
                Console.WriteLine('  RemotePath       : {0}', result['RemotePath'])
                Console.WriteLine('  Status           : {0}', result['Status'])
                Console.WriteLine('  ConnectionState  : {0}', result['ConnectionState'])
                Console.WriteLine('  Persistent       : {0}', result['Persistent'])
                Console.WriteLine('  UserName         : {0}', result['UserName'])
                Console.WriteLine('  Description      : {0}\r\n', result['Description'])
        except ex as Exception:
            Console.WriteLine('  [X] Exception: {0}', ex.Message)


    public static def ListNetworkShares():
        // lists current network shares for this system via WMI

        try:
            wmiData = ManagementObjectSearcher('root\\cimv2', 'SELECT * FROM Win32_Share')
            data as ManagementObjectCollection = wmiData.Get()

            Console.WriteLine('\r\n\r\n=== Network Shares (via WMI) ===\r\n')

            for result as ManagementObject in data:
                Console.WriteLine('  Name             : {0}', result['Name'])
                Console.WriteLine('  Path             : {0}', result['Path'])
                Console.WriteLine('  Description      : {0}\r\n', result['Description'])
        except ex as Exception:
            Console.WriteLine('  [X] Exception: {0}', ex.Message)


    public static def ListAntiVirusWMI():
        // lists installed VA products via WMI (the AntiVirusProduct class)

        try:
            wmiData = ManagementObjectSearcher('root\\SecurityCenter2', 'SELECT * FROM AntiVirusProduct')
            data as ManagementObjectCollection = wmiData.Get()

            Console.WriteLine('\r\n\r\n=== Registered Antivirus (via WMI) ===\r\n')

            for virusChecker as ManagementObject in data:
                Console.WriteLine('  Engine        : {0}', virusChecker['displayName'])
                Console.WriteLine('  ProductEXE    : {0}', virusChecker['pathToSignedProductExe'])
                Console.WriteLine('  ReportingEXE  : {0}\r\n', virusChecker['pathToSignedReportingExe'])
        except ex as Exception:
            Console.WriteLine('  [X] Exception: {0}', ex.Message)


    public static def ListInterestingProcesses():
        // TODO: check out https://github.com/harleyQu1nn/AggressorScripts/blob/master/ProcessColor.cna#L10

        // from https://github.com/threatexpress/red-team-scripts/blob/master/HostEnum.ps1#L985-L1033

        // TODO: cyberark? other password managers?

        OwnerInfo as (string)
        defensiveProcesses = Hashtable()
        interestingProcesses = Hashtable()
        browserProcesses = Hashtable()
        try:
            wmiQuery as string = string.Format('SELECT * FROM Win32_Process')
            searcher = ManagementObjectSearcher(wmiQuery)
            retObjectCollection as ManagementObjectCollection = searcher.Get()
            Console.WriteLine('\r\n\r\n=== Process Enumerations ===\r\n')
            Console.WriteLine('  * Potential Defensive Processes *\r\n')
            for Process as ManagementObject in retObjectCollection:
                for defensiveProcess as DictionaryEntry in defensiveProcesses:
                    if Process['Name'].ToString().ToLower() == defensiveProcess.Key.ToString().ToLower():
                        OwnerInfo = array(string, 2)
                        Process.InvokeMethod('GetOwner', (OwnerInfo cast (object)))

                        Console.WriteLine('\tName         : {0}', Process['Name'])
                        Console.WriteLine('\tProduct      : {0}', defensiveProcess.Value)
                        Console.WriteLine('\tProcessID    : {0}', Process['ProcessID'])
                        if OwnerInfo[0] is not null:
                            Console.WriteLine('\tOwner        : {0}\\{1}', OwnerInfo[1], OwnerInfo[0])
                        else:
                            Console.WriteLine('\tOwner        : ')
                        Console.WriteLine('\tCommandLine  : {0}\r\n', Process['CommandLine'])

            Console.WriteLine('\r\n  * Browser Processes *\r\n')

            for Process as ManagementObject in retObjectCollection:
                for browserProcess as DictionaryEntry in browserProcesses:
                    if Regex.IsMatch(Process['Name'].ToString(), browserProcess.Key.ToString(), RegexOptions.IgnoreCase):
                        OwnerInfo = array(string, 2)
                        Process.InvokeMethod('GetOwner', (OwnerInfo cast (object)))

                        Console.WriteLine('\tName         : {0}', Process['Name'])
                        Console.WriteLine('\tProduct      : {0}', browserProcess.Value)
                        Console.WriteLine('\tProcessID    : {0}', Process['ProcessID'])
                        if OwnerInfo[0] is not null:
                            Console.WriteLine('\tOwner        : {0}\\{1}', OwnerInfo[1], OwnerInfo[0])
                        else:
                            Console.WriteLine('\tOwner        : ')
                        Console.WriteLine('\tCommandLine  : {0}\r\n', Process['CommandLine'])

            Console.WriteLine('\r\n  * Other Interesting Processes *\r\n')

            for Process as ManagementObject in retObjectCollection:
                for interestingProcess as DictionaryEntry in interestingProcesses:
                    if Regex.IsMatch(Process['Name'].ToString(), interestingProcess.Key.ToString(), RegexOptions.IgnoreCase):
                        OwnerInfo = array(string, 2)
                        Process.InvokeMethod('GetOwner', (OwnerInfo cast (object)))

                        Console.WriteLine('\tName         : {0}', Process['Name'])
                        Console.WriteLine('\tProduct      : {0}', interestingProcess.Value)
                        Console.WriteLine('\tProcessID    : {0}', Process['ProcessID'])
                        if OwnerInfo[0] is not null:
                            Console.WriteLine('\tOwner        : {0}\\{1}', OwnerInfo[1], OwnerInfo[0])
                        else:
                            Console.WriteLine('\tOwner        : ')
                        Console.WriteLine('\tCommandLine  : {0}\r\n', Process['CommandLine'])
        except ex as Exception:
            Console.WriteLine('  [X] Exception: {0}', ex.Message)


    public static def ListRegistryAutoLogon():
        Console.WriteLine('\r\n\r\n=== Registry Auto-logon Settings ===\r\n')

        DefaultDomainName as string = GetRegValue('HKLM', 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon', 'DefaultDomainName')
        if DefaultDomainName != '':
            Console.WriteLine('  {0,-23} : {1}', 'DefaultDomainName', DefaultDomainName)

        DefaultUserName as string = GetRegValue('HKLM', 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon', 'DefaultUserName')
        if DefaultUserName != '':
            Console.WriteLine('  {0,-23} : {1}', 'DefaultUserName', DefaultUserName)

        DefaultPassword as string = GetRegValue('HKLM', 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon', 'DefaultPassword')
        if DefaultPassword != '':
            Console.WriteLine('  {0,-23} : {1}', 'DefaultPassword', DefaultPassword)

        AltDefaultDomainName as string = GetRegValue('HKLM', 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon', 'AltDefaultDomainName')
        if AltDefaultDomainName != '':
            Console.WriteLine('  {0,-23} : {1}', 'AltDefaultDomainName', AltDefaultDomainName)

        AltDefaultUserName as string = GetRegValue('HKLM', 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon', 'AltDefaultUserName')
        if AltDefaultDomainName != '':
            Console.WriteLine('  {0,-23} : {1}', 'AltDefaultUserName', AltDefaultUserName)

        AltDefaultPassword as string = GetRegValue('HKLM', 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon', 'AltDefaultPassword')
        if AltDefaultDomainName != '':
            Console.WriteLine('  {0,-23} : {1}', 'AltDefaultPassword', AltDefaultPassword)


    public static def ListRegistryAutoRuns():
        Console.WriteLine('\r\n\r\n=== Registry Autoruns ===')

        autorunLocations as (string) = (of string: 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run', 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce', 'SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run', 'SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce', 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunService', 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceService', 'SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunService', 'SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnceService')

        for autorunLocation as string in autorunLocations:
            settings as Dictionary[of string, object] = GetRegValues('HKLM', autorunLocation)
            if (settings is not null) and (settings.Count != 0):
                Console.WriteLine('\r\n  HKLM:\\{0} :', autorunLocation)
                for kvp as KeyValuePair[of string, object] in settings:
                    Console.WriteLine('    {0}', kvp.Value)


    public static def ListRDPSessions():
        // adapted from http://www.pinvoke.net/default.aspx/wtsapi32.wtsenumeratesessions
        server as IntPtr = IntPtr.Zero
        ret as List[of String] = List[of string]()
        server = OpenServer('localhost')

        Console.WriteLine('\r\n\r\n=== Current Host RDP Sessions (qwinsta) ===\r\n')

        try:
            ppSessionInfo as IntPtr = IntPtr.Zero

            count as Int32 = 0
            level as Int32 = 1
            retval as Int32 = WTSEnumerateSessionsEx(server, level, 0, ppSessionInfo, count)
            dataSize as Int32 = Marshal.SizeOf(typeof(WTS_SESSION_INFO_1))
            current = (ppSessionInfo cast Int64)

            if retval != 0:
                for i in range(0, count):
                    si = (Marshal.PtrToStructure((current cast System.IntPtr), typeof(WTS_SESSION_INFO_1)) cast WTS_SESSION_INFO_1)
                    current += dataSize

                    Console.WriteLine('  SessionID:       {0}', si.SessionID)
                    Console.WriteLine('  SessionName:     {0}', si.pSessionName)
                    Console.WriteLine('  UserName:        {0}', si.pUserName)
                    Console.WriteLine('  DomainName:      {0}', si.pDomainName)
                    Console.WriteLine('  State:           {0}', si.State)

                    // Now use WTSQuerySessionInformation to get the remote IP (if any) for the connection
                    addressPtr as IntPtr = IntPtr.Zero
                    bytes as uint = 0

                    WTSQuerySessionInformation(server, (si.SessionID cast uint), WTS_INFO_CLASS.WTSClientAddress, addressPtr, bytes)
                    address = (Marshal.PtrToStructure((addressPtr cast System.IntPtr), typeof(WTS_CLIENT_ADDRESS)) cast WTS_CLIENT_ADDRESS)

                    if address.Address[2] != 0:
                        sourceIP as string = String.Format('{0}.{1}.{2}.{3}', address.Address[2], address.Address[3], address.Address[4], address.Address[5])
                        Console.WriteLine('  SourceIP:        {0}\r\n', sourceIP)
                    else:
                        Console.WriteLine('  SourceIP: \r\n')

                WTSFreeMemory(ppSessionInfo)
        except ex as Exception:
            Console.WriteLine(ex)
        ensure:
            CloseServer(server)


    public static def ListFirewallRules():
        // lists local firewall policies and rules
        //      by default, only "deny" result are output unless "full" is passed

        if FilterResults.filter:
            Console.WriteLine('\r\n\r\n=== Firewall Rules (Deny) ===\r\n')
        else:
            Console.WriteLine('\r\n\r\n=== Firewall Rules (All) ===\r\n')

        try:
            // GUID for HNetCfg.FwPolicy2 COM object
            firewall as Type = Type.GetTypeFromCLSID(Guid('E2B3C97F-6AE1-41AC-817A-F6F92166D7DD'))
            firewallObj as Object = Activator.CreateInstance(firewall)
            types as Object = firewallObj.GetType().InvokeMember('CurrentProfileTypes', BindingFlags.GetProperty, null, firewallObj, null)

            Console.WriteLine('  Current Profile(s)          : {0}\r\n', (Int32.Parse(types.ToString()) cast FirewallProfiles))

            // NET_FW_PROFILE2_DOMAIN = 1, NET_FW_PROFILE2_PRIVATE = 2, NET_FW_PROFILE2_PUBLIC = 4
            enabledDomain as Object = firewallObj.GetType().InvokeMember('FirewallEnabled', BindingFlags.GetProperty, null, firewallObj, (of object: 1))
            Console.WriteLine('  FirewallEnabled (Domain)    : {0}', enabledDomain)
            enabledPrivate as Object = firewallObj.GetType().InvokeMember('FirewallEnabled', BindingFlags.GetProperty, null, firewallObj, (of object: 2))
            Console.WriteLine('  FirewallEnabled (Private)   : {0}', enabledPrivate)
            enabledPublic as Object = firewallObj.GetType().InvokeMember('FirewallEnabled', BindingFlags.GetProperty, null, firewallObj, (of object: 4))
            Console.WriteLine('  FirewallEnabled (Public)    : {0}\r\n', enabledPublic)

            // now grab all the rules
            rules as Object = firewallObj.GetType().InvokeMember('Rules', BindingFlags.GetProperty, null, firewallObj, null)

            // manually get the enumerator() method
            enumerator = (rules.GetType().InvokeMember('GetEnumerator', BindingFlags.InvokeMethod, null, rules, null) cast System.Collections.IEnumerator)

            // move to the first item
            enumerator.MoveNext()
            currentItem as Object = enumerator.Current

            while currentItem is not null:
                // only display enabled rules
                Enabled as Object = currentItem.GetType().InvokeMember('Enabled', BindingFlags.GetProperty, null, currentItem, null)
                if Enabled.ToString() == 'True':
                    Action as Object = currentItem.GetType().InvokeMember('Action', BindingFlags.GetProperty, null, currentItem, null)
                    if (FilterResults.filter and (Action.ToString() == '0')) or (not FilterResults.filter):
                        // extract all of our fields
                        Name as Object = currentItem.GetType().InvokeMember('Name', BindingFlags.GetProperty, null, currentItem, null)
                        Description as Object = currentItem.GetType().InvokeMember('Description', BindingFlags.GetProperty, null, currentItem, null)
                        Protocol as Object = currentItem.GetType().InvokeMember('Protocol', BindingFlags.GetProperty, null, currentItem, null)
                        ApplicationName as Object = currentItem.GetType().InvokeMember('ApplicationName', BindingFlags.GetProperty, null, currentItem, null)
                        LocalAddresses as Object = currentItem.GetType().InvokeMember('LocalAddresses', BindingFlags.GetProperty, null, currentItem, null)
                        LocalPorts as Object = currentItem.GetType().InvokeMember('LocalPorts', BindingFlags.GetProperty, null, currentItem, null)
                        RemoteAddresses as Object = currentItem.GetType().InvokeMember('RemoteAddresses', BindingFlags.GetProperty, null, currentItem, null)
                        RemotePorts as Object = currentItem.GetType().InvokeMember('RemotePorts', BindingFlags.GetProperty, null, currentItem, null)
                        Direction as Object = currentItem.GetType().InvokeMember('Direction', BindingFlags.GetProperty, null, currentItem, null)
                        Profiles as Object = currentItem.GetType().InvokeMember('Profiles', BindingFlags.GetProperty, null, currentItem, null)

                        ruleAction = 'ALLOW'
                        if Action.ToString() != '1':
                            ruleAction = 'DENY'

                        ruleDirection = 'IN'
                        if Direction.ToString() != '1':
                            ruleDirection = 'OUT'

                        ruleProtocol = 'TCP'
                        if Protocol.ToString() != '6':
                            ruleProtocol = 'UDP'
                        // TODO: other protocols!

                        Console.WriteLine('  Name                 : {0}', Name)
                        Console.WriteLine('  Description          : {0}', Description)
                        Console.WriteLine('  ApplicationName      : {0}', ApplicationName)
                        Console.WriteLine('  Protocol             : {0}', ruleProtocol)
                        Console.WriteLine('  Action               : {0}', ruleAction)
                        Console.WriteLine('  Direction            : {0}', ruleDirection)
                        Console.WriteLine('  Profiles             : {0}', (Int32.Parse(Profiles.ToString()) cast FirewallProfiles))
                        Console.WriteLine('  Local Addr:Port      : {0}:{1}', LocalAddresses, LocalPorts)
                        Console.WriteLine('  Remote Addr:Port     : {0}:{1}\r\n', RemoteAddresses, RemotePorts)
                // manually move the enumerator
                enumerator.MoveNext()
                currentItem = enumerator.Current
            Marshal.ReleaseComObject(firewallObj)
            firewallObj = null
        except ex as Exception:
            Console.WriteLine('  [X] Exception: {0}', ex)


    public static def ListDNSCache():
        Console.WriteLine('\r\n\r\n=== DNS Cache (via WMI) ===\r\n')

        // lists the local DNS cache via WMI (MSFT_DNSClientCache class)
        try:
            wmiData = ManagementObjectSearcher('root\\standardcimv2', 'SELECT * FROM MSFT_DNSClientCache')
            data as ManagementObjectCollection = wmiData.Get()

            for result as ManagementObject in data:
                Console.WriteLine('  Entry         : {0}', result['Entry'])
                Console.WriteLine('  Name          : {0}', result['Name'])
                Console.WriteLine('  Data          : {0}\r\n', result['Data'])

        except ex as ManagementException:
            if ex.ErrorCode == ManagementStatus.InvalidNamespace:
                Console.WriteLine("  [X] 'MSFT_DNSClientCache' WMI class unavailable (minimum supported versions of Windows: 8/2012)", ex.Message)
        except ex as Exception:
            Console.WriteLine('  [X] Exception: {0}', ex.Message)


    public static def ListARPTable():
        // adapted from Fred's code at https://social.technet.microsoft.com/Forums/lync/en-US/e949b8d6-17ad-4afc-88cd-0019a3ac9df9/powershell-alternative-to-arp-a?forum=ITCG

        Console.WriteLine('\r\n\r\n=== Current ARP Table ===')

        try:
            adapters as Dictionary[of int, string] = Dictionary[of int, string]()
            hostNames as Dictionary[of string, string] = Dictionary[of string, string]()

            // build a mapping of index -> interface information
            for ni as NetworkInterface in NetworkInterface.GetAllNetworkInterfaces():
                if ni is not null:
                    adapterProperties as IPInterfaceProperties = ni.GetIPProperties()
                    if adapterProperties is not null:
                        dnsServers = ''
                        dnsServerList as List[of string] = List[of string]()
                        dnsServerCollection as IPAddressCollection = adapterProperties.DnsAddresses
                        if dnsServerCollection.Count > 0:
                            for dns as IPAddress in dnsServerCollection:
                                dnsServerList.Add(dns.ToString())
                            dnsServers = String.Join(', ', dnsServerList.ToArray())

                        try:
                            p as IPv4InterfaceProperties = adapterProperties.GetIPv4Properties()
                            if p is not null:
                                ips = ArrayList()

                                for info as UnicastIPAddressInformation in adapterProperties.UnicastAddresses:
                                    if Regex.IsMatch(info.Address.ToString(), '^(\\d+)\\.(\\d+)\\.(\\d+)\\.(\\d+)$'):
                                        // grab all the IPv4 addresses
                                        ips.Add(info.Address.ToString())
                                // build a "Ethernet1 (172.16.213.246) --- Index 8" type string for the index
                                description as string = String.Format('{0} ({1}) --- Index {2}', ni.Name, string.Join(',', (ips.ToArray(Type.GetType('System.String')) cast (string))), p.Index)
                                if not String.IsNullOrEmpty(dnsServers):
                                    description += String.Format('\r\n    DNS Servers : {0}\r\n', dnsServers)
                                adapters.Add(p.Index, description)
                        except :
                            pass

            bytesNeeded = 0

            result as int = GetIpNetTable(IntPtr.Zero, bytesNeeded, false)

            // call the function, expecting an insufficient buffer.
            if result != ERROR_INSUFFICIENT_BUFFER:
                Console.WriteLine('  [X] Exception: {0}', result)

            buffer as IntPtr = IntPtr.Zero

            // allocate sufficient memory for the result structure
            buffer = Marshal.AllocCoTaskMem(bytesNeeded)

            result = GetIpNetTable(buffer, bytesNeeded, false)

            if result != 0:
                Console.WriteLine('  [X] Exception allocating buffer: {0}', result)

            // now we have the buffer, we have to marshal it. We can read the first 4 bytes to get the length of the buffer
            entries as int = Marshal.ReadInt32(buffer)

            // increment the memory pointer by the size of the int
            currentBuffer = IntPtr((buffer.ToInt64() + Marshal.SizeOf(typeof(int))))

            // allocate a list of entries
            arpEntries as List[of MIB_IPNETROW] = List[of MIB_IPNETROW]()
            for index in range(0, entries):

            // cycle through the entries
                arpEntries.Add((Marshal.PtrToStructure(IntPtr((currentBuffer.ToInt64() + (index * Marshal.SizeOf(typeof(MIB_IPNETROW))))), typeof(MIB_IPNETROW)) cast MIB_IPNETROW))

            // sort the list by interface index
            sortedARPEntries as List[of MIB_IPNETROW] = arpEntries.OrderBy({ o | return o.dwIndex }).ToList()
            currentIndexAdaper as int = (-1)

            for arpEntry as MIB_IPNETROW in sortedARPEntries:
                indexAdapter as int = arpEntry.dwIndex

                if currentIndexAdaper != indexAdapter:
                    if adapters.ContainsKey(indexAdapter):
                        Console.WriteLine('\r\n\r\n  Interface     : {0}', adapters[indexAdapter])
                    else:
                        Console.WriteLine('\r\n\r\n  Interface     : n/a --- Index {0}', indexAdapter)
                    Console.WriteLine('    Internet Address      Physical Address      Type')
                    currentIndexAdaper = indexAdapter

                ipAddr = IPAddress(BitConverter.GetBytes(arpEntry.dwAddr))
                macBytes as (byte) = (of byte: arpEntry.mac0, arpEntry.mac1, arpEntry.mac2, arpEntry.mac3, arpEntry.mac4, arpEntry.mac5)
                physAddr as string = BitConverter.ToString(macBytes)
                entryType = (arpEntry.dwType cast ArpEntryType)

                Console.WriteLine(String.Format('    {0,-22}{1,-22}{2}', ipAddr, physAddr, entryType))

            FreeMibTable(buffer)
        except ex as Exception:
            Console.WriteLine('  [X] Exception: {0}', ex)


    // helper that gets a service name from a service tag
    private static def GetServiceNameFromTag(ProcessId as uint, ServiceTag as uint) as string:
        serviceTagQuery = SC_SERVICE_TAG_QUERY()

        res as uint = I_QueryTagInformation(IntPtr.Zero, SC_SERVICE_TAG_QUERY_TYPE.ServiceNameFromTagInformation, serviceTagQuery)
        if res == ERROR_SUCCESS:
            return Marshal.PtrToStringUni(serviceTagQuery.Buffer)
        else:
            return null


    public static def ListAllTcpConnections():
        AF_INET = 2
        // IP_v4
        tableBufferSize as uint = 0
        ret as uint = 0
        tableBuffer as IntPtr = IntPtr.Zero
        rowPtr as IntPtr = IntPtr.Zero
        ownerModuleTable as MIB_TCPTABLE_OWNER_MODULE
        TcpRows as (MIB_TCPROW_OWNER_MODULE)
        processes as Dictionary[of string, string] = Dictionary[of string, string]()

        Console.WriteLine('\r\n\r\n=== Active TCP Network Connections ===\r\n')

        try:
            // Adapted from https://stackoverflow.com/questions/577433/which-pid-listens-on-a-given-port-in-c-sharp/577660#577660
            // Build a PID -> process name lookup table
            searcher = ManagementObjectSearcher('SELECT * FROM Win32_Process')
            retObjectCollection as ManagementObjectCollection = searcher.Get()

            for Process as ManagementObject in retObjectCollection:
                if Process['CommandLine'] is not null:
                    processes.Add(Process['ProcessId'].ToString(), Process['CommandLine'].ToString())
                else:
                    processes.Add(Process['ProcessId'].ToString(), Process['Name'].ToString())

            // Figure out how much memory we need for the result struct
            ret = GetExtendedTcpTable(IntPtr.Zero, tableBufferSize, true, AF_INET, TCP_TABLE_CLASS.TCP_TABLE_OWNER_MODULE_ALL, 0)
            if (ret != ERROR_SUCCESS) and (ret != ERROR_INSUFFICIENT_BUFFER):
                // 122 == insufficient buffer size
                Console.WriteLine(' [X] Bad check value from GetExtendedTcpTable : {0}', ret)
                return

            tableBuffer = Marshal.AllocHGlobal((tableBufferSize cast int))

            ret = GetExtendedTcpTable(tableBuffer, tableBufferSize, true, AF_INET, TCP_TABLE_CLASS.TCP_TABLE_OWNER_MODULE_ALL, 0)
            if ret != ERROR_SUCCESS:
                Console.WriteLine(' [X] Bad return value from GetExtendedTcpTable : {0}', ret)
                return

            // get the number of entries in the table
            ownerModuleTable = (Marshal.PtrToStructure(tableBuffer, typeof(MIB_TCPTABLE_OWNER_MODULE)) cast MIB_TCPTABLE_OWNER_MODULE)
            rowPtr = ((tableBuffer.ToInt64() + Marshal.OffsetOf(typeof(MIB_TCPTABLE_OWNER_MODULE), 'Table').ToInt64()) cast IntPtr)
            TcpRows = array(MIB_TCPROW_OWNER_MODULE, ownerModuleTable.NumEntries)
            for i in range(0, ownerModuleTable.NumEntries):

                tcpRow = (Marshal.PtrToStructure(rowPtr, typeof(MIB_TCPROW_OWNER_MODULE)) cast MIB_TCPROW_OWNER_MODULE)
                TcpRows[i] = tcpRow
                // next entry
                rowPtr = (((rowPtr cast long) + Marshal.SizeOf(tcpRow)) cast IntPtr)

            Console.WriteLine('  Local Address          Foreign Address        State      PID   Service         ProcessName')
            for entry as MIB_TCPROW_OWNER_MODULE in TcpRows:
                processName = ''
                try:
                    processName = processes[entry.OwningPid.ToString()]
                except :
                    pass

                serviceName as string = GetServiceNameFromTag(entry.OwningPid, (entry.OwningModuleInfo0 cast uint))

                Console.WriteLine(String.Format('  {0,-23}{1,-23}{2,-11}{3,-6}{4,-15} {5}', ((entry.LocalAddress + ':') + entry.LocalPort), ((entry.RemoteAddress + ':') + entry.RemotePort), entry.State, entry.OwningPid, serviceName, processName))
        except ex as Exception:
            Console.WriteLine('  [X] Exception: {0}', ex.Message)
        ensure:
            if tableBuffer != IntPtr.Zero:
                Marshal.FreeHGlobal(tableBuffer)


    public static def ListAllUdpConnections():
        AF_INET = 2
        // IP_v4
        tableBufferSize as uint = 0
        ret as uint = 0
        tableBuffer as IntPtr = IntPtr.Zero
        rowPtr as IntPtr = IntPtr.Zero
        ownerModuleTable as MIB_UDPTABLE_OWNER_MODULE
        UdpRows as (MIB_UDPROW_OWNER_MODULE)
        processes as Dictionary[of string, string] = Dictionary[of string, string]()

        Console.WriteLine('\r\n\r\n=== Active UDP Network Connections ===\r\n')

        try:
            // Adapted from https://stackoverflow.com/questions/577433/which-pid-listens-on-a-given-port-in-c-sharp/577660#577660
            // Build a PID -> process name lookup table
            searcher = ManagementObjectSearcher('SELECT * FROM Win32_Process')
            retObjectCollection as ManagementObjectCollection = searcher.Get()

            for Process as ManagementObject in retObjectCollection:
                if Process['CommandLine'] is not null:
                    processes.Add(Process['ProcessId'].ToString(), Process['CommandLine'].ToString())
                else:
                    processes.Add(Process['ProcessId'].ToString(), Process['Name'].ToString())

            // Figure out how much memory we need for the result struct
            ret = GetExtendedUdpTable(IntPtr.Zero, tableBufferSize, true, AF_INET, UDP_TABLE_CLASS.UDP_TABLE_OWNER_MODULE, 0)
            if (ret != ERROR_SUCCESS) and (ret != ERROR_INSUFFICIENT_BUFFER):
                // 122 == insufficient buffer size
                Console.WriteLine(' [X] Bad check value from GetExtendedUdpTable : {0}', ret)
                return

            tableBuffer = Marshal.AllocHGlobal((tableBufferSize cast int))

            ret = GetExtendedUdpTable(tableBuffer, tableBufferSize, true, AF_INET, UDP_TABLE_CLASS.UDP_TABLE_OWNER_MODULE, 0)
            if ret != ERROR_SUCCESS:
                Console.WriteLine(' [X] Bad return value from GetExtendedUdpTable : {0}', ret)
                return

            // get the number of entries in the table
            ownerModuleTable = (Marshal.PtrToStructure(tableBuffer, typeof(MIB_UDPTABLE_OWNER_MODULE)) cast MIB_UDPTABLE_OWNER_MODULE)
            rowPtr = ((tableBuffer.ToInt64() + Marshal.OffsetOf(typeof(MIB_UDPTABLE_OWNER_MODULE), 'Table').ToInt64()) cast IntPtr)
            UdpRows = array(MIB_UDPROW_OWNER_MODULE, ownerModuleTable.NumEntries)
            for i in range(0, ownerModuleTable.NumEntries):

                udpRow = (Marshal.PtrToStructure(rowPtr, typeof(MIB_UDPROW_OWNER_MODULE)) cast MIB_UDPROW_OWNER_MODULE)
                UdpRows[i] = udpRow
                // next entry
                rowPtr = (((rowPtr cast long) + Marshal.SizeOf(udpRow)) cast IntPtr)

            Console.WriteLine('  Local Address          PID    Service                 ProcessName')
            for entry as MIB_UDPROW_OWNER_MODULE in UdpRows:
                processName = ''
                try:
                    processName = processes[entry.OwningPid.ToString()]
                except :
                    pass

                serviceName as string = GetServiceNameFromTag(entry.OwningPid, (entry.OwningModuleInfo0 cast uint))

                Console.WriteLine(String.Format('  {0,-23}{1,-7}{2,-23} {3}', ((entry.LocalAddress + ':') + entry.LocalPort), entry.OwningPid, serviceName, processName))
        except ex as Exception:
            Console.WriteLine('  [X] Exception: {0}', ex.Message)
        ensure:
            if tableBuffer != IntPtr.Zero:
                Marshal.FreeHGlobal(tableBuffer)

    public static def ListNonstandardProcesses():
        // lists currently running processes that don't have "Microsoft Corporation" as the company name in their file info
        //      or all processes if "full" is passed

        if FilterResults.filter:
            Console.WriteLine('\r\n\r\n=== Non Microsoft Processes (via WMI) ===\r\n')
        else:
            Console.WriteLine('\r\n\r\n=== All Processes (via WMI) ===\r\n')

        try:
            wmiQueryString as string = 'SELECT ProcessId, ExecutablePath, CommandLine FROM Win32_Process'
            using searcher = ManagementObjectSearcher(wmiQueryString):
                using results = searcher.Get():
                    for p as Process in Process.GetProcesses():
                        for mo as ManagementObject in results:
                            if p.Id == mo['ProcessID']:
                                //OLD -  if ((item.Path != null) && ((!FilterResults.filter) || (!Regex.IsMatch(item.Path, "C:\\\\WINDOWS\\\\", RegexOptions.IgnoreCase))))
                                Path as string = mo['ExecutablePath']
                                _Process as Process = p
                                CommandLine as string =  mo['CommandLine']

                                if Path is not null:
                                    myFileVersionInfo as FileVersionInfo = FileVersionInfo.GetVersionInfo(Path)
                                    companyName as string = myFileVersionInfo.CompanyName
                                    if (String.IsNullOrEmpty(companyName) or (not FilterResults.filter)) or (not Regex.IsMatch(companyName, '^Microsoft.*', RegexOptions.IgnoreCase)):
                                        isDotNet = false
                                        try:
                                            myAssemblyName as AssemblyName = AssemblyName.GetAssemblyName(Path)
                                            isDotNet = true
                                        except converterGeneratedName7 as System.IO.FileNotFoundException:
                                            pass
                                        // System.Console.WriteLine("The file cannot be found.");
                                        except exception as System.BadImageFormatException:
                                            if Regex.IsMatch(exception.Message, '.*This assembly is built by a runtime newer than the currently loaded runtime and cannot be loaded.*', RegexOptions.IgnoreCase):
                                                isDotNet = true
                                        except :
                                            pass
                                        // System.Console.WriteLine("The assembly has already been loaded.");

                                        Console.WriteLine('  Name           : {0}', _Process.ProcessName)
                                        Console.WriteLine('  Company Name   : {0}', companyName)
                                        Console.WriteLine('  PID            : {0}', _Process.Id)
                                        Console.WriteLine('  Path           : {0}', Path)
                                        Console.WriteLine('  CommandLine    : {0}', CommandLine)
                                        Console.WriteLine('  IsDotNet       : {0}\r\n', isDotNet)
        except ex as Exception:
            Console.WriteLine('  [X] Exception: {0}', ex.Message)

    // elevated system checks
    public static def List4624Events():
        eventId = '4624'

        // grab events from the last X days - 7 for default, 30 for "full" collection
        lastDays = 7

        if not FilterResults.filter:
            lastDays = 30

        startTime = System.DateTime.Now.AddDays(-lastDays)
        endTime = System.DateTime.Now

        Console.WriteLine('\r\n\r\n=== 4624 Account Logon Events (last {0} days) ===\r\n', lastDays)

        query= string.Format('*[System/EventID={0}] and *[System[TimeCreated[@SystemTime >= \'{1}\']]] and *[System[TimeCreated[@SystemTime <= \'{2}\']]]', eventId, startTime.ToUniversalTime().ToString('o'), endTime.ToUniversalTime().ToString('o'))

        eventsQuery = EventLogQuery('Security', PathType.LogName, query)
        eventsQuery.ReverseDirection = true

        try:
            logReader = EventLogReader(eventsQuery)

            eventdetail as EventRecord = logReader.ReadEvent()
            goto converterGeneratedName8
            while true:
                eventdetail = logReader.ReadEvent()
                :converterGeneratedName8
                break  unless (eventdetail is not null)
                //string SubjectUserSid = eventdetail.Properties[0].Value.ToString();
                //string SubjectUserName = eventdetail.Properties[1].Value.ToString();
                //string SubjectDomainName = eventdetail.Properties[2].Value.ToString();
                //string SubjectLogonId = eventdetail.Properties[3].Value.ToString();
                TargetUserSid as string = eventdetail.Properties[4].Value.ToString()
                TargetUserName as string = eventdetail.Properties[5].Value.ToString()
                TargetDomainName as string = eventdetail.Properties[6].Value.ToString()
                //string TargetLogonId = eventdetail.Properties[7].Value.ToString();
                //string LogonType = eventdetail.Properties[8].Value.ToString();
                LogonType as string = String.Format('{0}', (Int32.Parse(eventdetail.Properties[8].Value.ToString()) cast SECURITY_LOGON_TYPE))
                //string LogonProcessName = eventdetail.Properties[9].Value.ToString();
                AuthenticationPackageName as string = eventdetail.Properties[10].Value.ToString()
                WorkstationName as string = eventdetail.Properties[11].Value.ToString()
                //string LogonGuid = eventdetail.Properties[12].Value.ToString();
                //string TransmittedServices = eventdetail.Properties[13].Value.ToString();
                LmPackageName as string = eventdetail.Properties[14].Value.ToString()
                //string KeyLength = eventdetail.Properties[15].Value.ToString();
                //string ProcessId = eventdetail.Properties[16].Value.ToString();
                ProcessName as string = eventdetail.Properties[17].Value.ToString()
                //string IpAddress = eventdetail.Properties[18].Value.ToString();
                //string IpPort = eventdetail.Properties[19].Value.ToString();
                //string ImpersonationLevel = eventdetail.Properties[20].Value.ToString();
                //string RestrictedAdminMode = eventdetail.Properties[21].Value.ToString();
                //string TargetOutboundUserName = eventdetail.Properties[22].Value.ToString();
                //string TargetOutboundDomainName = eventdetail.Properties[23].Value.ToString();
                //string VirtualAccount = eventdetail.Properties[24].Value.ToString();
                //string TargetLinkedLogonId = eventdetail.Properties[25].Value.ToString();
                //string ElevatedToken = eventdetail.Properties[26].Value.ToString();

                // filter out SYSTEM, computer accounts, local service accounts, UMFD-X accounts, and DWM-X accounts (for now)
                ignoreRegex = Regex('SYSTEM|\\$$|LOCAL SERVICE|NETWORK SERVICE|UMFD-[0-9]+|DWM-[0-9]+|ANONYMOUS LOGON')
                m as Match = ignoreRegex.Match(TargetUserName)
                if not m.Success:
                    Console.WriteLine('  UserName          : {0}', TargetUserName)
                    Console.WriteLine('  UserDomain        : {0}', TargetDomainName)
                    Console.WriteLine('  UserSID           : {0}', TargetUserSid)
                    Console.WriteLine('  ProcessName       : {0}', ProcessName)
                    Console.WriteLine('  LogonType         : {0}', LogonType)
                    Console.WriteLine('  AuthPKG           : {0}', AuthenticationPackageName)
                    Console.WriteLine('  LmPackageName     : {0}', LmPackageName)
                    Console.WriteLine('  WorkstationName   : {0}', WorkstationName)
                    Console.WriteLine('  TimeCreated       : {0}\r\n', eventdetail.TimeCreated.ToString())

                    //Console.WriteLine(eventdetail.FormatDescription());
                    //break;
        except ex as Exception:
            Console.WriteLine('  [X] Exception: {0}', ex.Message)


    public static def List4648Events():
        eventId = '4648'

        // grab events from the last X days - 7 for default, 30 for "full" collection
        lastDays = 7

        if not FilterResults.filter:
            lastDays = 30

        startTime  = System.DateTime.Now.AddDays(-lastDays)
        endTime = System.DateTime.Now

        Console.WriteLine('\r\n\r\n=== 4624 Explicit Credential Events (last {0} days) - Runas or Outbound RDP ===\r\n', lastDays)


        query = string.Format('*[System/EventID={0}] and *[System[TimeCreated[@SystemTime >= \'{1}\']]] and *[System[TimeCreated[@SystemTime <= \'{2}\']]]', eventId, startTime.ToUniversalTime().ToString('o'), endTime.ToUniversalTime().ToString('o'))

        eventsQuery = EventLogQuery('Security', PathType.LogName, query)
        eventsQuery.ReverseDirection = true

        try:
            logReader = EventLogReader(eventsQuery)

            eventdetail as EventRecord = logReader.ReadEvent()
            goto converterGeneratedName9
            while true:
                eventdetail = logReader.ReadEvent()
                :converterGeneratedName9
                break  unless (eventdetail is not null)
                SubjectUserSid as string = eventdetail.Properties[0].Value.ToString()
                SubjectUserName as string = eventdetail.Properties[1].Value.ToString()
                SubjectDomainName as string = eventdetail.Properties[2].Value.ToString()
                //string SubjectLogonId = eventdetail.Properties[3].Value.ToString();
                //string LogonGuid = eventdetail.Properties[4].Value.ToString();
                TargetUserName as string = eventdetail.Properties[5].Value.ToString()
                TargetDomainName as string = eventdetail.Properties[6].Value.ToString()
                //string TargetLogonGuid = eventdetail.Properties[7].Value.ToString();
                TargetServerName as string = eventdetail.Properties[8].Value.ToString()
                //string TargetInfo = eventdetail.Properties[9].Value.ToString();
                //string ProcessId = eventdetail.Properties[10].Value.ToString();
                ProcessName as string = eventdetail.Properties[11].Value.ToString()
                //string IpAddress = eventdetail.Properties[12].Value.ToString();
                //string IpPort = eventdetail.Properties[13].Value.ToString();

                // filter out accounts (for now)
                ignoreRegex = Regex('\\$$')
                m as Match = ignoreRegex.Match(SubjectUserName)
                if not m.Success:
                    Console.WriteLine('  SubjectUserName        : {0}', SubjectUserName)
                    Console.WriteLine('  SubjectDomainName      : {0}', SubjectDomainName)
                    Console.WriteLine('  SubjectUserSid         : {0}', SubjectUserSid)
                    Console.WriteLine('  TargetUserName         : {0}', TargetUserName)
                    Console.WriteLine('  TargetDomainName       : {0}', TargetDomainName)
                    Console.WriteLine('  TargetServerName       : {0}', TargetServerName)
                    Console.WriteLine('  ProcessName            : {0}', ProcessName)
                    Console.WriteLine('  TimeCreated            : {0}\r\n', eventdetail.TimeCreated.ToString())
        except ex as Exception:
            Console.WriteLine('  [X] Exception: {0}', ex.Message)


    public static def ListSysmonConfig():
        Console.WriteLine('\r\n\r\n=== Sysmon Configuration ===\r\n')

        hashing as string = GetRegValue('HKLM', 'SYSTEM\\CurrentControlSet\\Services\\SysmonDrv\\Parameters', 'HashingAlgorithm')
        if not String.IsNullOrEmpty(hashing):
            Console.WriteLine('  Hashing algorithm: {0}', hashing)

        options as string = GetRegValue('HKLM', 'SYSTEM\\CurrentControlSet\\Services\\SysmonDrv\\Parameters', 'Options')
        if not String.IsNullOrEmpty(options):
            Console.WriteLine('  Options: {0}', options)

        sysmonRules as (byte) = GetRegValueBytes('HKLM', 'SYSTEM\\CurrentControlSet\\Services\\SysmonDrv\\Parameters', 'Rules')
        if sysmonRules is not null:
            Console.WriteLine(('  Sysmon rules: ' + Convert.ToBase64String(sysmonRules)))



    // user-focused checks
    public static def ListCurrentDomainGroups():
        try:
            Console.WriteLine('\r\n\r\n=== Current User\'s Groups ===\r\n')

            wi as WindowsIdentity = WindowsIdentity.GetCurrent()
            groups as List[of string] = List[of string]()

            for group as IdentityReference in wi.Groups:
                try:
                    groups.Add(group.Translate(typeof(NTAccount)).ToString())
                except :
                    pass
            groups.Sort()
            for group as string in groups:
                Console.WriteLine('  {0}', group)
        except ex as Exception:
            Console.WriteLine('  [X] Exception: {0}', ex.Message)


    public static def ListSavedRDPConnections():
        //shows saved RDP connections, including username hints (if present)

        usernameHint as string
        subkeys as (string)
        if IsHighIntegrity():
            SIDs as (string) = Registry.Users.GetSubKeyNames()
            for SID as string in SIDs:
                if SID.StartsWith('S-1-5') and (not SID.EndsWith('_Classes')):
                    subkeys = GetRegSubkeys('HKU', String.Format('{0}\\Software\\Microsoft\\Terminal Server Client\\Servers', SID))
                    if subkeys is not null:
                        Console.WriteLine('\r\n\r\n=== Saved RDP Connection Information ({0}) ===', SID)
                        for host as string in subkeys:
                            usernameHint = GetRegValue('HKCU', String.Format('Software\\Microsoft\\Terminal Server Client\\Servers\\{0}', host), 'UsernameHint')
                            Console.WriteLine('\r\n  Host           : {0}', host)
                            if usernameHint != '':
                                Console.WriteLine('    UsernameHint : {0}', usernameHint)
        else:
            Console.WriteLine('\r\n\r\n=== Saved RDP Connection Information (Current User) ===')
            subkeys = GetRegSubkeys('HKCU', 'Software\\Microsoft\\Terminal Server Client\\Servers')
            if subkeys is not null:
                for host as string in subkeys:
                    usernameHint = GetRegValue('HKCU', String.Format('Software\\Microsoft\\Terminal Server Client\\Servers\\{0}', host), 'UsernameHint')
                    Console.WriteLine('\r\n  Host           : {0}', host)
                    if usernameHint != '':
                        Console.WriteLine('    UsernameHint : {0}', usernameHint)


    public static def ListMasterKeys():
        // lists any found DPAPI master keys



        fileName as string
        lastModified as DateTime
        lastAccessed as DateTime
        files as (string)
        directories as (string)
        userDPAPIBasePath as string
        userName as string
        try:
            if IsHighIntegrity():
                Console.WriteLine('\r\n\r\n=== Checking for DPAPI Master Keys (All Users) ===\r\n')
                userFolder as string = String.Format('{0}\\Users\\', Environment.GetEnvironmentVariable('SystemDrive'))
                dirs as (string) = Directory.GetDirectories(userFolder)
                for dir as string in dirs:
                    parts as (string) = dir.Split(char('\\'))
                    userName = parts[(parts.Length - 1)]
                    if not (((dir.EndsWith('Public') or dir.EndsWith('Default')) or dir.EndsWith('Default User')) or dir.EndsWith('All Users')):
                        userDPAPIBasePath = String.Format('{0}\\AppData\\Roaming\\Microsoft\\Protect\\', dir)
                        if System.IO.Directory.Exists(userDPAPIBasePath):
                            directories = Directory.GetDirectories(userDPAPIBasePath)
                            for directory as string in directories:
                                files = Directory.GetFiles(directory)
                                Console.WriteLine('    Folder       : {0}\r\n', directory)
                                for file as string in files:
                                    if Regex.IsMatch(file, '[0-9A-Fa-f]{8}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{12}'):
                                        lastAccessed = System.IO.File.GetLastAccessTime(file)
                                        lastModified = System.IO.File.GetLastWriteTime(file)
                                        fileName = System.IO.Path.GetFileName(file)
                                        Console.WriteLine('    MasterKey    : {0}', fileName)
                                        Console.WriteLine('        Accessed : {0}', lastAccessed)
                                        Console.WriteLine('        Modified : {0}\r\n', lastModified)
                                Console.WriteLine()
                Console.WriteLine('  [*] Use the Mimikatz "dpapi::masterkey" module with appropriate arguments (/pvk or /rpc) to decrypt')
                Console.WriteLine('  [*] You can also extract many DPAPI masterkeys from memory with the Mimikatz "sekurlsa::dpapi" module')
            else:
                Console.WriteLine('\r\n\r\n=== Checking for DPAPI Master Keys (Current User) ===\r\n')
                userName = Environment.GetEnvironmentVariable('USERNAME')
                userDPAPIBasePath = String.Format('{0}\\AppData\\Roaming\\Microsoft\\Protect\\', System.Environment.GetEnvironmentVariable('USERPROFILE'))

                if System.IO.Directory.Exists(userDPAPIBasePath):
                    directories = Directory.GetDirectories(userDPAPIBasePath)
                    for directory as string in directories:
                        files = Directory.GetFiles(directory)

                        Console.WriteLine('    Folder       : {0}\r\n', directory)

                        for file as string in files:
                            if Regex.IsMatch(file, '[0-9A-Fa-f]{8}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{12}'):
                                lastAccessed = System.IO.File.GetLastAccessTime(file)
                                lastModified = System.IO.File.GetLastWriteTime(file)
                                fileName = System.IO.Path.GetFileName(file)
                                Console.WriteLine('    MasterKey    : {0}', fileName)
                                Console.WriteLine('        Accessed : {0}', lastAccessed)
                                Console.WriteLine('        Modified : {0}\r\n', lastModified)
                Console.WriteLine('  [*] Use the Mimikatz "dpapi::masterkey" module with appropriate arguments (/rpc) to decrypt')
        except ex as Exception:
            Console.WriteLine('  [X] Exception: {0}', ex.Message)


    public static def ListCredFiles():
        // lists any found files in Local\Microsoft\Credentials\*




        // jankily parse the bytes to extract the credential type and master key GUID
        // reference- https://github.com/gentilkiwi/mimikatz/blob/3d8be22fff9f7222f9590aa007629e18300cf643/modules/kull_m_dpapi.h#L24-L54



        desc as string
        descBytes as (byte)
        descLen as int
        stringLenArray as (byte)
        guidMasterKey as Guid
        guidMasterKeyArray as (byte)
        credentialArray as (byte)
        fileName as string
        size as long
        lastModified as DateTime
        lastAccessed as DateTime

        files as (string)
        found as bool
        userCredFilePath as string
        userName as string
        try:
            if IsHighIntegrity():
                Console.WriteLine('\r\n\r\n=== Checking for Credential Files (All Users) ===\r\n')
                userFolder as string = String.Format('{0}\\Users\\', Environment.GetEnvironmentVariable('SystemDrive'))
                dirs as (string) = Directory.GetDirectories(userFolder)
                found = false
                for dir as string in dirs:
                    parts as (string) = dir.Split(char('\\'))
                    userName = parts[(parts.Length - 1)]
                    if not (((dir.EndsWith('Public') or dir.EndsWith('Default')) or dir.EndsWith('Default User')) or dir.EndsWith('All Users')):
                        userCredFilePath = String.Format('{0}\\AppData\\Local\\Microsoft\\Credentials\\', dir)
                        if System.IO.Directory.Exists(userCredFilePath):
                            systemFiles as (string) = Directory.GetFiles(userCredFilePath)
                            if (systemFiles is not null) and (systemFiles.Length != 0):
                                Console.WriteLine('\r\n    Folder       : {0}\r\n', userCredFilePath)
                                for file as string in systemFiles:
                                    lastAccessed = System.IO.File.GetLastAccessTime(file)
                                    lastModified = System.IO.File.GetLastWriteTime(file)
                                    size = System.IO.FileInfo(file).Length
                                    fileName = System.IO.Path.GetFileName(file)
                                    found = true
                                    Console.WriteLine('    CredFile     : {0}', fileName)
                                    credentialArray = File.ReadAllBytes(file)
                                    guidMasterKeyArray = array(byte, 16)
                                    Array.Copy(credentialArray, 36, guidMasterKeyArray, 0, 16)
                                    guidMasterKey = Guid(guidMasterKeyArray)
                                    stringLenArray = array(byte, 16)
                                    Array.Copy(credentialArray, 56, stringLenArray, 0, 4)
                                    descLen = BitConverter.ToInt32(stringLenArray, 0)
                                    descBytes = array(byte, descLen)
                                    Array.Copy(credentialArray, 60, descBytes, 0, (descLen - 4))
                                    desc = Encoding.Unicode.GetString(descBytes)
                                    Console.WriteLine('    Description  : {0}', desc)
                                    Console.WriteLine('    MasterKey    : {0}', guidMasterKey.ToString())
                                    Console.WriteLine('    Accessed     : {0}', lastAccessed)
                                    Console.WriteLine('    Modified     : {0}', lastModified)
                                    Console.WriteLine('    Size         : {0}\r\n', size)
                systemFolder as string = String.Format('{0}\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Credentials', Environment.GetEnvironmentVariable('SystemRoot'))
                files = Directory.GetFiles(systemFolder)
                if (files is not null) and (files.Length != 0):
                    Console.WriteLine('\r\n    Folder       : {0}\r\n', systemFolder)

                    for file as string in files:
                        lastAccessed = System.IO.File.GetLastAccessTime(file)
                        lastModified = System.IO.File.GetLastWriteTime(file)
                        size = System.IO.FileInfo(file).Length
                        fileName = System.IO.Path.GetFileName(file)
                        found = true
                        Console.WriteLine('    CredFile     : {0}', fileName)

                        // jankily parse the bytes to extract the credential type and master key GUID
                        // reference- https://github.com/gentilkiwi/mimikatz/blob/3d8be22fff9f7222f9590aa007629e18300cf643/modules/kull_m_dpapi.h#L24-L54
                        credentialArray = File.ReadAllBytes(file)
                        guidMasterKeyArray = array(byte, 16)
                        Array.Copy(credentialArray, 36, guidMasterKeyArray, 0, 16)
                        guidMasterKey = Guid(guidMasterKeyArray)

                        stringLenArray = array(byte, 16)
                        Array.Copy(credentialArray, 56, stringLenArray, 0, 4)
                        descLen = BitConverter.ToInt32(stringLenArray, 0)

                        descBytes = array(byte, descLen)
                        Array.Copy(credentialArray, 60, descBytes, 0, (descLen - 4))

                        desc = Encoding.Unicode.GetString(descBytes)
                        Console.WriteLine('    Description  : {0}', desc)
                        Console.WriteLine('    MasterKey    : {0}', guidMasterKey.ToString())
                        Console.WriteLine('    Accessed     : {0}', lastAccessed)
                        Console.WriteLine('    Modified     : {0}', lastModified)
                        Console.WriteLine('    Size         : {0}\r\n', size)

                if found:
                    Console.WriteLine('  [*] Use the Mimikatz "dpapi::cred" module with appropriate /masterkey to decrypt')
                    Console.WriteLine('  [*] You can extract many DPAPI masterkeys from memory with the Mimikatz "sekurlsa::dpapi" module')
            else:
                Console.WriteLine('\r\n\r\n=== Checking for Credential Files (Current User) ===\r\n')
                userName = Environment.GetEnvironmentVariable('USERNAME')
                userCredFilePath = String.Format('{0}\\AppData\\Local\\Microsoft\\Credentials\\', System.Environment.GetEnvironmentVariable('USERPROFILE'))
                found = false

                if System.IO.Directory.Exists(userCredFilePath):
                    files = Directory.GetFiles(userCredFilePath)
                    Console.WriteLine('    Folder       : {0}\r\n', userCredFilePath)

                    for file as string in files:
                        lastAccessed = System.IO.File.GetLastAccessTime(file)
                        lastModified = System.IO.File.GetLastWriteTime(file)
                        size = System.IO.FileInfo(file).Length
                        fileName = System.IO.Path.GetFileName(file)
                        found = true
                        Console.WriteLine('    CredFile     : {0}', fileName)

                        // jankily parse the bytes to extract the credential type and master key GUID
                        // reference- https://github.com/gentilkiwi/mimikatz/blob/3d8be22fff9f7222f9590aa007629e18300cf643/modules/kull_m_dpapi.h#L24-L54
                        credentialArray = File.ReadAllBytes(file)
                        guidMasterKeyArray = array(byte, 16)
                        Array.Copy(credentialArray, 36, guidMasterKeyArray, 0, 16)
                        guidMasterKey = Guid(guidMasterKeyArray)

                        stringLenArray = array(byte, 16)
                        Array.Copy(credentialArray, 56, stringLenArray, 0, 4)
                        descLen = BitConverter.ToInt32(stringLenArray, 0)

                        descBytes = array(byte, descLen)
                        Array.Copy(credentialArray, 60, descBytes, 0, (descLen - 4))

                        desc = Encoding.Unicode.GetString(descBytes)
                        Console.WriteLine('    Description  : {0}', desc)
                        Console.WriteLine('    MasterKey    : {0}', guidMasterKey.ToString())
                        Console.WriteLine('    Accessed     : {0}', lastAccessed)
                        Console.WriteLine('    Modified     : {0}', lastModified)
                        Console.WriteLine('    Size         : {0}\r\n', size)
                if found:
                    Console.WriteLine('  [*] Use the Mimikatz "dpapi::cred" module with appropriate /masterkey to decrypt')
        except ex as Exception:
            Console.WriteLine('  [X] Exception: {0}', ex.Message)


    public static def ListRDCManFiles():
        // lists any found files in Local\Microsoft\Credentials\*



        // grab the recent RDG files

        lastModified as DateTime
        lastAccessed as DateTime
        node as XmlNode
        items as XmlNodeList
        filesToOpen as XmlNodeList
        xmlDoc as XmlDocument
        userRDManFile as string
        userName as string
        found as bool
        try:
            if IsHighIntegrity():
                Console.WriteLine('\r\n\r\n=== Checking for RDCMan Settings Files (All Users) ===\r\n')
                userFolder as string = String.Format('{0}\\Users\\', Environment.GetEnvironmentVariable('SystemDrive'))
                dirs as (string) = Directory.GetDirectories(userFolder)
                found = false
                for dir as string in dirs:
                    parts as (string) = dir.Split(char('\\'))
                    userName = parts[(parts.Length - 1)]
                    if not (((dir.EndsWith('Public') or dir.EndsWith('Default')) or dir.EndsWith('Default User')) or dir.EndsWith('All Users')):
                        userRDManFile = String.Format('{0}\\AppData\\Local\\Microsoft\\Remote Desktop Connection Manager\\RDCMan.settings', dir)
                        if System.IO.File.Exists(userRDManFile):
                            xmlDoc = XmlDocument()
                            xmlDoc.Load(userRDManFile)
                            filesToOpen = xmlDoc.GetElementsByTagName('FilesToOpen')
                            items = filesToOpen[0].ChildNodes
                            node = items[0]
                            lastAccessed = System.IO.File.GetLastAccessTime(userRDManFile)
                            lastModified = System.IO.File.GetLastWriteTime(userRDManFile)
                            Console.WriteLine('    RDCManFile   : {0}', userRDManFile)
                            Console.WriteLine('    Accessed     : {0}', lastAccessed)
                            Console.WriteLine('    Modified     : {0}', lastModified)

                            for rdgFile as XmlNode in items:
                                found = true
                                Console.WriteLine('      .RDG File  : {0}', rdgFile.InnerText)
                            Console.WriteLine()

                if found:
                    Console.WriteLine('  [*] Use the Mimikatz "dpapi::rdg" module with appropriate /masterkey to decrypt any .rdg files')
                    Console.WriteLine('  [*] You can extract many DPAPI masterkeys from memory with the Mimikatz "sekurlsa::dpapi" module')
            else:
                Console.WriteLine('\r\n\r\n=== Checking for RDCMan Settings Files (Current User) ===\r\n')
                found = false
                userName = Environment.GetEnvironmentVariable('USERNAME')
                userRDManFile = String.Format('{0}\\AppData\\Local\\Microsoft\\Remote Desktop Connection Manager\\RDCMan.settings', System.Environment.GetEnvironmentVariable('USERPROFILE'))

                if System.IO.File.Exists(userRDManFile):
                    xmlDoc = XmlDocument()
                    xmlDoc.Load(userRDManFile)

                    // grab the recent RDG files
                    filesToOpen = xmlDoc.GetElementsByTagName('FilesToOpen')
                    items = filesToOpen[0].ChildNodes
                    node = items[0]

                    lastAccessed = System.IO.File.GetLastAccessTime(userRDManFile)
                    lastModified = System.IO.File.GetLastWriteTime(userRDManFile)
                    Console.WriteLine('    RDCManFile   : {0}', userRDManFile)
                    Console.WriteLine('    Accessed     : {0}', lastAccessed)
                    Console.WriteLine('    Modified     : {0}', lastModified)

                    for rdgFile as XmlNode in items:
                        found = true
                        Console.WriteLine('      .RDG File  : {0}', rdgFile.InnerText)
                    Console.WriteLine()
                if found:
                    Console.WriteLine('  [*] Use the Mimikatz "dpapi::rdg" module with appropriate /masterkey to decrypt any .rdg files')
                    Console.WriteLine('  [*] You can extract many DPAPI masterkeys from memory with the Mimikatz "sekurlsa::dpapi" module')
        except ex as Exception:
            Console.WriteLine('  [X] Exception: {0}', ex.Message)


    public static def ListIETabs():
        // Lists currently open Internet Explorer tabs, via COM
        // Notes:
        //  https://searchcode.com/codesearch/view/9859954/
        //  https://gist.github.com/yizhang82/a1268d3ea7295a8a1496e01d60ada816

        Console.WriteLine('\r\n\r\n=== Internet Explorer Open Tabs ===\r\n')

        try:
            // Shell.Application COM GUID
            shell as Type = Type.GetTypeFromCLSID(Guid('13709620-C279-11CE-A49E-444553540000'))

            // actually instantiate the Shell.Application COM object
            shellObj as Object = Activator.CreateInstance(shell)

            // grab all the current windows
            windows as Object = shellObj.GetType().InvokeMember('Windows', BindingFlags.InvokeMethod, null, shellObj, null)

            // grab the open tab count
            openTabs as Object = windows.GetType().InvokeMember('Count', BindingFlags.GetProperty, null, windows, null)
            openTabsCount as int = Int32.Parse(openTabs.ToString())
            for i in range(0, openTabsCount):

                // grab the acutal tab
                item as Object = windows.GetType().InvokeMember('Item', BindingFlags.InvokeMethod, null, windows, (of object: i))
                try:
                    // extract the tab properties
                    locationName as Object = item.GetType().InvokeMember('LocationName', BindingFlags.GetProperty, null, item, null)
                    locationURL as Object = item.GetType().InvokeMember('LocationUrl', BindingFlags.GetProperty, null, item, null)

                    // ensure we have a site address
                    if Regex.IsMatch(locationURL.ToString(), '(^https?://.+)|(^ftp://)'):
                        Console.WriteLine('  Location Name : {0}', locationName)
                        Console.WriteLine('  Location URL  : {0}\r\n', locationURL)
                    Marshal.ReleaseComObject(item)
                    item = null
                except :
                    pass
                //
            Marshal.ReleaseComObject(windows)
            windows = null
            Marshal.ReleaseComObject(shellObj)
            shellObj = null
        except ex2 as Exception:
            Console.WriteLine('  [X] Exception: {0}', ex2)

    public static def TriageIE():
        // lists Internt explorer history (last 7 days by default) and favorites

        url as string
        line as string
        bookmarkPaths as (string)
        userIEBookmarkPath as string
        urlTime as DateTime
        timeLong as long
        timeBytes as (byte)
        settings as Dictionary[of string, object]
        lastDays = 7
        if not FilterResults.filter:
            lastDays = 90
        startTime as DateTime = System.DateTime.Now.AddDays(-lastDays)
        try:
            if IsHighIntegrity():
                Console.WriteLine('\r\n\r\n=== Internet Explorer (All Users) Last {0} Days ===', lastDays)
                SIDs as (string) = Registry.Users.GetSubKeyNames()
                for SID as string in SIDs:
                    if SID.StartsWith('S-1-5') and (not SID.EndsWith('_Classes')):
                        settings = GetRegValues('HKU', String.Format('{0}\\SOFTWARE\\Microsoft\\Internet Explorer\\TypedURLs', SID))
                        if (settings is not null) and (settings.Count > 1):
                            Console.WriteLine('\r\n  History ({0}):', SID)
                            for kvp as KeyValuePair[of string, object] in settings:
                                timeBytes = GetRegValueBytes('HKU', String.Format('{0}\\SOFTWARE\\Microsoft\\Internet Explorer\\TypedURLsTime', SID), kvp.Key.ToString().Trim())
                                if timeBytes is not null:
                                    timeLong = (BitConverter.ToInt64(timeBytes, 0) cast long)
                                    urlTime = DateTime.FromFileTime(timeLong)
                                    if urlTime > startTime:
                                        Console.WriteLine('    {0,-23} :  {1}', urlTime, kvp.Value.ToString().Trim())
                userFolder as string = String.Format('{0}\\Users\\', Environment.GetEnvironmentVariable('SystemDrive'))
                dirs as (string) = Directory.GetDirectories(userFolder)
                for dir as string in dirs:
                    parts as (string) = dir.Split(char('\\'))
                    userName as string = parts[(parts.Length - 1)]
                    if not (((dir.EndsWith('Public') or dir.EndsWith('Default')) or dir.EndsWith('Default User')) or dir.EndsWith('All Users')):
                        userIEBookmarkPath = String.Format('{0}\\Favorites\\', dir)
                        if Directory.Exists(userIEBookmarkPath):
                            bookmarkPaths = Directory.GetFiles(userIEBookmarkPath, '*.url', SearchOption.AllDirectories)
                            if bookmarkPaths.Length != 0:
                                Console.WriteLine('\r\n  Favorites ({0}):', userName)
                                for bookmarkPath as string in bookmarkPaths:
                                    using rdr = StreamReader(bookmarkPath):
                                        url = ''
                                        while (line = rdr.ReadLine()) is not null:
                                            if line.StartsWith('URL=', StringComparison.InvariantCultureIgnoreCase):
                                                if line.Length > 4:
                                                    url = line.Substring(4)
                                                break
                                        Console.WriteLine('    {0}', url.ToString().Trim())
            else:
                Console.WriteLine('\r\n\r\n=== Internet Explorer (Current User) Last {0} Days ===', lastDays)

                Console.WriteLine('\r\n  History:')
                settings = GetRegValues('HKCU', 'SOFTWARE\\Microsoft\\Internet Explorer\\TypedURLs')
                if (settings is not null) and (settings.Count != 0):
                    for kvp as KeyValuePair[of string, object] in settings:
                        timeBytes = GetRegValueBytes('HKCU', 'SOFTWARE\\Microsoft\\Internet Explorer\\TypedURLsTime', kvp.Key.ToString().Trim())
                        if timeBytes is not null:
                            timeLong = (BitConverter.ToInt64(timeBytes, 0) cast long)
                            urlTime = DateTime.FromFileTime(timeLong)
                            if urlTime > startTime:
                                Console.WriteLine('    {0,-23} :  {1}', urlTime, kvp.Value.ToString().Trim())


                Console.WriteLine('\r\n  Favorites:')
                userIEBookmarkPath = String.Format('{0}\\Favorites\\', System.Environment.GetEnvironmentVariable('USERPROFILE'))

                bookmarkPaths = Directory.GetFiles(userIEBookmarkPath, '*.url', SearchOption.AllDirectories)

                for bookmarkPath as string in bookmarkPaths:
                    using rdr = StreamReader(bookmarkPath):
                        url = ''
                        while (line = rdr.ReadLine()) is not null:
                            if line.StartsWith('URL=', StringComparison.InvariantCultureIgnoreCase):
                                if line.Length > 4:
                                    url = line.Substring(4)
                                break
                        Console.WriteLine('    {0}', url.ToString().Trim())
        except ex as Exception:
            Console.WriteLine('  [X] Exception: {0}', ex)



    public static def GetVaultElementValue(vaultElementPtr as IntPtr) as object:
        // Helper function to extract the ItemValue field from a VAULT_ITEM_ELEMENT struct
        // pulled directly from @djhohnstein's SharpWeb project: https://github.com/djhohnstein/SharpWeb/blob/master/Edge/SharpEdge.cs
        results as object
        partialElement as object = System.Runtime.InteropServices.Marshal.PtrToStructure(vaultElementPtr, typeof(VaultCli.VAULT_ITEM_ELEMENT))
        partialElementInfo as FieldInfo = partialElement.GetType().GetField('Type')
        partialElementType = partialElementInfo.GetValue(partialElement)

        elementPtr = ((vaultElementPtr.ToInt64() + 16) cast IntPtr)
        converterGeneratedName10 = (partialElementType cast int)
        if converterGeneratedName10 == 7:
            // VAULT_ELEMENT_TYPE == String; These are the plaintext passwords!
            StringPtr as IntPtr = System.Runtime.InteropServices.Marshal.ReadIntPtr(elementPtr)
            results = System.Runtime.InteropServices.Marshal.PtrToStringUni(StringPtr)
        elif converterGeneratedName10 == 0:
            // VAULT_ELEMENT_TYPE == bool
            results = System.Runtime.InteropServices.Marshal.ReadByte(elementPtr)
            results = (results cast bool)
        elif converterGeneratedName10 == 1:
            // VAULT_ELEMENT_TYPE == Short
            results = System.Runtime.InteropServices.Marshal.ReadInt16(elementPtr)
        elif converterGeneratedName10 == 2:
            // VAULT_ELEMENT_TYPE == Unsigned Short
            results = System.Runtime.InteropServices.Marshal.ReadInt16(elementPtr)
        elif converterGeneratedName10 == 3:
            // VAULT_ELEMENT_TYPE == Int
            results = System.Runtime.InteropServices.Marshal.ReadInt32(elementPtr)
        elif converterGeneratedName10 == 4:
            // VAULT_ELEMENT_TYPE == Unsigned Int
            results = System.Runtime.InteropServices.Marshal.ReadInt32(elementPtr)
        elif converterGeneratedName10 == 5:
            // VAULT_ELEMENT_TYPE == Double
            results = System.Runtime.InteropServices.Marshal.PtrToStructure(elementPtr, typeof(Double))
        elif converterGeneratedName10 == 6:
            // VAULT_ELEMENT_TYPE == GUID
            results = System.Runtime.InteropServices.Marshal.PtrToStructure(elementPtr, typeof(Guid))
        elif converterGeneratedName10 == 12:
            // VAULT_ELEMENT_TYPE == Sid
            sidPtr as IntPtr = System.Runtime.InteropServices.Marshal.ReadIntPtr(elementPtr)
            sidObject = System.Security.Principal.SecurityIdentifier(sidPtr)
            results = sidObject.Value
        else:
            /* Several VAULT_ELEMENT_TYPES are currently unimplemented according to
                     * Lord Graeber. Thus we do not implement them. */

            results = null
        return results

    public static def DumpVault():
        // pulled directly from @djhohnstein's SharpWeb project: https://github.com/djhohnstein/SharpWeb/blob/master/Edge/SharpEdge.cs
        Console.WriteLine('\r\n\r\n=== Checking Windows Vaults ===')
        OSVersion = Environment.OSVersion.Version
        OSMajor = OSVersion.Major
        OSMinor = OSVersion.Minor

        VAULT_ITEM as Type

        if (OSMajor >= 6) and (OSMinor >= 2):
            VAULT_ITEM = typeof(VaultCli.VAULT_ITEM_WIN8)
        else:
            VAULT_ITEM = typeof(VaultCli.VAULT_ITEM_WIN7)

        vaultCount as Int32 = 0
        vaultGuidPtr as IntPtr = IntPtr.Zero
        result = VaultCli.VaultEnumerateVaults(0, vaultCount, vaultGuidPtr)

        //var result = CallVaultEnumerateVaults(VaultEnum, 0, ref vaultCount, ref vaultGuidPtr);

        if (result cast int) != 0:
            Console.WriteLine((('  [ERROR] Unable to enumerate vaults. Error (0x' + result.ToString()) + ')'))
            return

        // Create dictionary to translate Guids to human readable elements
        guidAddress as IntPtr = vaultGuidPtr
        vaultSchema as Dictionary[of Guid, string] = Dictionary[of Guid, string]()
        vaultSchema.Add(Guid('2F1A6504-0641-44CF-8BB5-3612D865F2E5'), 'Windows Secure Note')
        vaultSchema.Add(Guid('3CCD5499-87A8-4B10-A215-608888DD3B55'), 'Windows Web Password Credential')
        vaultSchema.Add(Guid('154E23D0-C644-4E6F-8CE6-5069272F999F'), 'Windows Credential Picker Protector')
        vaultSchema.Add(Guid('4BF4C442-9B8A-41A0-B380-DD4A704DDB28'), 'Web Credentials')
        vaultSchema.Add(Guid('77BC582B-F0A6-4E15-4E80-61736B6F3B29'), 'Windows Credentials')
        vaultSchema.Add(Guid('E69D7838-91B5-4FC9-89D5-230D4D4CC2BC'), 'Windows Domain Certificate Credential')
        vaultSchema.Add(Guid('3E0E35BE-1B77-43E7-B873-AED901B6275B'), 'Windows Domain Password Credential')
        vaultSchema.Add(Guid('3C886FF3-2669-4AA2-A8FB-3F6759A77548'), 'Windows Extended Credential')
        vaultSchema.Add(Guid('00000000-0000-0000-0000-000000000000'), null)
        for i in range(0, vaultCount):

            // Open vault block
            vaultGuidString as object = System.Runtime.InteropServices.Marshal.PtrToStructure(guidAddress, typeof(Guid))
            vaultGuid = Guid(vaultGuidString.ToString())
            guidAddress = ((guidAddress.ToInt64() + System.Runtime.InteropServices.Marshal.SizeOf(typeof(Guid))) cast IntPtr)
            vaultHandle as IntPtr = IntPtr.Zero
            vaultType as string
            if vaultSchema.ContainsKey(vaultGuid):
                vaultType = vaultSchema[vaultGuid]
            else:
                vaultType = vaultGuid.ToString()
            result = VaultCli.VaultOpenVault(vaultGuid, (0 cast UInt32), vaultHandle)
            if result != 0:
                Console.WriteLine(((('  [ERROR] Unable to open the following vault: ' + vaultType) + '. Error: 0x') + result.ToString()))
                return
            // Vault opened successfully! Continue.


            Console.WriteLine('\r\n  Vault GUID     : {0}', vaultGuid)
            Console.WriteLine('  Vault Type     : {0}\r\n', vaultType)

            // Fetch all items within Vault
            vaultItemCount = 0
            vaultItemPtr as IntPtr = IntPtr.Zero
            result = VaultCli.VaultEnumerateItems(vaultHandle, 512, vaultItemCount, vaultItemPtr)
            if result != 0:
                Console.WriteLine(((('  [ERROR] Unable to enumerate vault items from the following vault: ' + vaultType) + '. Error 0x') + result.ToString()))
                return
            structAddress = vaultItemPtr
            if vaultItemCount > 0:
                for j in range(1, (vaultItemCount + 1)):
                // For each vault item...
                    // Begin fetching vault item...
                    currentItem = System.Runtime.InteropServices.Marshal.PtrToStructure(structAddress, VAULT_ITEM)
                    structAddress = ((structAddress.ToInt64() + System.Runtime.InteropServices.Marshal.SizeOf(VAULT_ITEM)) cast IntPtr)

                    passwordVaultItem as IntPtr = IntPtr.Zero
                    // Field Info retrieval
                    schemaIdInfo as FieldInfo = currentItem.GetType().GetField('SchemaId')
                    schemaId = Guid(schemaIdInfo.GetValue(currentItem).ToString())
                    pResourceElementInfo as FieldInfo = currentItem.GetType().GetField('pResourceElement')
                    pResourceElement = (pResourceElementInfo.GetValue(currentItem) cast IntPtr)
                    pIdentityElementInfo as FieldInfo = currentItem.GetType().GetField('pIdentityElement')
                    pIdentityElement = (pIdentityElementInfo.GetValue(currentItem) cast IntPtr)
                    dateTimeInfo as FieldInfo = currentItem.GetType().GetField('LastModified')
                    lastModified = (dateTimeInfo.GetValue(currentItem) cast UInt64)

                    pPackageSid as IntPtr = IntPtr.Zero
                    if (OSMajor >= 6) and (OSMinor >= 2):
                        // Newer versions have package sid
                        pPackageSidInfo as FieldInfo = currentItem.GetType().GetField('pPackageSid')
                        pPackageSid = (pPackageSidInfo.GetValue(currentItem) cast IntPtr)
                        result = VaultCli.VaultGetItem_WIN8(vaultHandle, schemaId, pResourceElement, pIdentityElement, pPackageSid, IntPtr.Zero, 0, passwordVaultItem)
                    else:
                        result = VaultCli.VaultGetItem_WIN7(vaultHandle, schemaId, pResourceElement, pIdentityElement, IntPtr.Zero, 0, passwordVaultItem)

                    if result != 0:
                        Console.WriteLine(('  [ERROR] occured while retrieving vault item. Error: 0x' + result.ToString()))
                        return
                    passwordItem as object = System.Runtime.InteropServices.Marshal.PtrToStructure(passwordVaultItem, VAULT_ITEM)
                    pAuthenticatorElementInfo as FieldInfo = passwordItem.GetType().GetField('pAuthenticatorElement')
                    pAuthenticatorElement = (pAuthenticatorElementInfo.GetValue(passwordItem) cast IntPtr)
                    // Fetch the credential from the authenticator element
                    cred as object = GetVaultElementValue(pAuthenticatorElement)
                    packageSid as object = null
                    if pPackageSid != IntPtr.Zero:
                        packageSid = GetVaultElementValue(pPackageSid)
                    if cred is not null:
                        // Indicates successful fetch
                        // Console.WriteLine("  --- IE/Edge Credential ---");
                        // Console.WriteLine("  Vault Type   : {0}", vaultType);
                        resource as object = GetVaultElementValue(pResourceElement)
                        if resource is not null:
                            Console.WriteLine('    Resource     : {0}', resource)
                        identity as object = GetVaultElementValue(pIdentityElement)
                        if identity is not null:
                            Console.WriteLine('    Identity     : {0}', identity)
                        if packageSid is not null:
                            Console.WriteLine('    PacakgeSid  : {0}', packageSid)
                        Console.WriteLine('    Credential   : {0}', cred)
                        // Stupid datetime
                        Console.WriteLine('    LastModified : {0}', System.DateTime.FromFileTimeUtc((lastModified cast long)))
                        Console.WriteLine()


    public static def CheckChrome():
        // checks if Chrome has a history database

        userChromeLoginDataPath as string
        userChromeCookiesPath as string
        userChromeHistoryPath as string
        try:
            if IsHighIntegrity():
                Console.WriteLine('\r\n\r\n=== Checking for Chrome (All Users) ===\r\n')
                userFolder as string = String.Format('{0}\\Users\\', Environment.GetEnvironmentVariable('SystemDrive'))
                dirs as (string) = Directory.GetDirectories(userFolder)
                for dir as string in dirs:
                    found = false
                    parts as (string) = dir.Split(char('\\'))
                    userName as string = parts[(parts.Length - 1)]
                    if not (((dir.EndsWith('Public') or dir.EndsWith('Default')) or dir.EndsWith('Default User')) or dir.EndsWith('All Users')):
                        userChromeHistoryPath = String.Format('{0}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History', dir)
                        if System.IO.File.Exists(userChromeHistoryPath):
                            Console.WriteLine('  [*] Chrome history file exists at {0}', userChromeHistoryPath)
                            Console.WriteLine('      Run the \'TriageChrome\' command\r\n')
                            found = true
                        userChromeCookiesPath = String.Format('{0}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cookies', dir)
                        if System.IO.File.Exists(userChromeCookiesPath):
                            Console.WriteLine('  [*] Chrome cookies database exists at {0}', userChromeCookiesPath)
                            Console.WriteLine('      Run the Mimikatz "dpapi::chrome" module\r\n')
                            found = true
                        userChromeLoginDataPath = String.Format('{0}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data', dir)
                        if System.IO.File.Exists(userChromeLoginDataPath):
                            Console.WriteLine('  [*] Chrome saved login database exists at {0}', userChromeLoginDataPath)
                            Console.WriteLine('      Run the Mimikatz "dpapi::chrome" module or SharpWeb (https://github.com/djhohnstein/SharpWeb)\r\n')
                            found = true
                        if found:
                            Console.WriteLine()
            else:
                Console.WriteLine('\r\n\r\n=== Checking for Chrome (Current User) ===\r\n')
                userChromeHistoryPath = String.Format('{0}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History', System.Environment.GetEnvironmentVariable('USERPROFILE'))
                if System.IO.File.Exists(userChromeHistoryPath):
                    Console.WriteLine('  [*] Chrome history file exists at {0}', userChromeHistoryPath)
                    Console.WriteLine('      Run the \'TriageChrome\' command\r\n')
                userChromeCookiesPath = String.Format('{0}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cookies', System.Environment.GetEnvironmentVariable('USERPROFILE'))
                if System.IO.File.Exists(userChromeCookiesPath):
                    Console.WriteLine('  [*] Chrome cookies database exists at {0}', userChromeCookiesPath)
                    Console.WriteLine('      Run the Mimikatz "dpapi::chrome" module\r\n')
                userChromeLoginDataPath = String.Format('{0}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data', System.Environment.GetEnvironmentVariable('USERPROFILE'))
                if System.IO.File.Exists(userChromeLoginDataPath):
                    Console.WriteLine('  [*] Chrome saved login database exists at {0}', userChromeLoginDataPath)
                    Console.WriteLine('      Run the Mimikatz "dpapi::chrome" module or SharpWeb (https://github.com/djhohnstein/SharpWeb)')
        except ex as Exception:
            Console.WriteLine('  [X] Exception: {0}', ex.Message)

    public static def ParseChromeHistory(path as string, user as string):
        // parses a Chrome history file via regex
        if System.IO.File.Exists(path):
            Console.WriteLine('\r\n    History ({0}):\r\n', user)
            historyRegex = Regex('(http|ftp|https|file)://([\\w_-]+(?:(?:\\.[\\w_-]+)+))([\\w.,@?^=%&:/~+#-]*[\\w@?^=%&/~+#-])?')

            try:
                using r = StreamReader(path):
                    line as string
                    while (line = r.ReadLine()) is not null:
                        m as Match = historyRegex.Match(line)
                        if m.Success:
                            Console.WriteLine('      {0}', m.Groups[0].ToString().Trim())
            except exception as System.IO.IOException:
                Console.WriteLine('\r\n    [x] IO exception, history file likely in use (i.e. Browser is likely running): ', exception.Message)
            except exception as Exception:
                Console.WriteLine('\r\n    [x] Exception: {0}', exception.Message)

    public static def ParseChromeBookmarks(path as string, user as string):
        // parses a Chrome bookmarks
        if System.IO.File.Exists(path):
            Console.WriteLine('\r\n    Bookmarks ({0}):\r\n', user)

            try:
                contents as string = System.IO.File.ReadAllText(path)

                // reference: http://www.tomasvera.com/programming/using-javascriptserializer-to-parse-json-objects/
                json = JavaScriptSerializer()
                deserialized as Dictionary[of string, object] = json.Deserialize[of Dictionary[of string, object]](contents)
                roots = (deserialized['roots'] cast Dictionary[of string, object])
                bookmark_bar = (roots['bookmark_bar'] cast Dictionary[of string, object])
                children = (bookmark_bar['children'] cast System.Collections.ArrayList)

                for entry as Dictionary[of string, object] in children:
                    Console.WriteLine('      Name: {0}', entry['name'].ToString().Trim())
                    Console.WriteLine('      Url:  {0}\r\n', entry['url'].ToString().Trim())
            except exception as System.IO.IOException:
                Console.WriteLine('\r\n    [x] IO exception, Bookmarks file likely in use (i.e. Chrome is likely running).', exception.Message)
            except exception as Exception:
                Console.WriteLine('\r\n    [x] Exception: {0}', exception.Message)

    public static def TriageChrome():


        userChromeBookmarkPath as string
        userChromeHistoryPath as string
        try:
            if IsHighIntegrity():
                Console.WriteLine('\r\n\r\n=== Chrome (All Users) ===')
                userFolder as string = String.Format('{0}\\Users\\', Environment.GetEnvironmentVariable('SystemDrive'))
                dirs as (string) = Directory.GetDirectories(userFolder)
                for dir as string in dirs:
                    parts as (string) = dir.Split(char('\\'))
                    userName as string = parts[(parts.Length - 1)]
                    if not (((dir.EndsWith('Public') or dir.EndsWith('Default')) or dir.EndsWith('Default User')) or dir.EndsWith('All Users')):
                        userChromeHistoryPath = String.Format('{0}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History', dir)
                        ParseChromeHistory(userChromeHistoryPath, userName)
                        userChromeBookmarkPath = String.Format('{0}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Bookmarks', dir)
                        ParseChromeBookmarks(userChromeBookmarkPath, userName)
            else:
                Console.WriteLine('\r\n\r\n=== Chrome (Current User) ===')

                userChromeHistoryPath = String.Format('{0}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History', System.Environment.GetEnvironmentVariable('USERPROFILE'))
                ParseChromeHistory(userChromeHistoryPath, System.Environment.GetEnvironmentVariable('USERNAME'))

                userChromeBookmarkPath = String.Format('{0}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Bookmarks', System.Environment.GetEnvironmentVariable('USERPROFILE'))

                ParseChromeBookmarks(userChromeBookmarkPath, System.Environment.GetEnvironmentVariable('USERNAME'))
        except ex as Exception:
            Console.WriteLine('  [X] Exception: {0}', ex.Message)


    public static def CheckFirefox():
        // checks if Firefox has a history database
        firefoxCredentialFile4 as string
        firefoxCredentialFile3 as string
        firefoxHistoryFile as string
        directories as (string)
        userFirefoxBasePath as string
        userName as string
        try:
            if IsHighIntegrity():
                Console.WriteLine('\r\n\r\n=== Checking for Firefox (All Users) ===\r\n')
                userFolder as string = String.Format('{0}\\Users\\', Environment.GetEnvironmentVariable('SystemDrive'))
                dirs as (string) = Directory.GetDirectories(userFolder)
                for dir as string in dirs:
                    parts as (string) = dir.Split(char('\\'))
                    userName = parts[(parts.Length - 1)]
                    if not (((dir.EndsWith('Public') or dir.EndsWith('Default')) or dir.EndsWith('Default User')) or dir.EndsWith('All Users')):
                        found = false
                        userFirefoxBasePath = String.Format('{0}\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\', dir)
                        if System.IO.Directory.Exists(userFirefoxBasePath):
                            directories = Directory.GetDirectories(userFirefoxBasePath)
                            for directory as string in directories:
                                firefoxHistoryFile = String.Format('{0}\\{1}', directory, 'places.sqlite')
                                if System.IO.File.Exists(firefoxHistoryFile):
                                    Console.WriteLine('  [*] Firefox history file exists at {0}', firefoxHistoryFile)
                                    Console.WriteLine('      Run the \'TriageFirefox\' command\r\n')
                                    found = true
                                firefoxCredentialFile3 = String.Format('{0}\\{1}', directory, 'key3.db')
                                if System.IO.File.Exists(firefoxCredentialFile3):
                                    Console.WriteLine('  [*] Firefox credential file exists at {0}', firefoxCredentialFile3)
                                    Console.WriteLine('      Run SharpWeb (https://github.com/djhohnstein/SharpWeb) \r\n')
                                    found = true
                                firefoxCredentialFile4 = String.Format('{0}\\{1}', directory, 'key4.db')
                                if System.IO.File.Exists(firefoxCredentialFile4):
                                    Console.WriteLine('  [*] Firefox credential file exists at {0}', firefoxCredentialFile4)
                                    Console.WriteLine('      Run SharpWeb (https://github.com/djhohnstein/SharpWeb) \r\n')
                                    found = true
                            if found:
                                Console.WriteLine()
            else:
                Console.WriteLine('\r\n\r\n=== Checking for Firefox (Current User) ===\r\n')
                userName = Environment.GetEnvironmentVariable('USERNAME')
                userFirefoxBasePath = String.Format('{0}\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\', System.Environment.GetEnvironmentVariable('USERPROFILE'))

                if System.IO.Directory.Exists(userFirefoxBasePath):
                    directories = Directory.GetDirectories(userFirefoxBasePath)
                    for directory as string in directories:
                        firefoxHistoryFile = String.Format('{0}\\{1}', directory, 'places.sqlite')
                        if System.IO.File.Exists(firefoxHistoryFile):
                            Console.WriteLine('  [*] Firefox history file exists at {0}', firefoxHistoryFile)
                            Console.WriteLine('      Run the \'TriageFirefox\' command\r\n')
                        firefoxCredentialFile3 = String.Format('{0}\\{1}', directory, 'key3.db')
                        if System.IO.File.Exists(firefoxCredentialFile3):
                            Console.WriteLine('  [*] Firefox credential file exists at {0}', firefoxCredentialFile3)
                            Console.WriteLine('      Run SharpWeb (https://github.com/djhohnstein/SharpWeb)\r\n')
                        firefoxCredentialFile4 = String.Format('{0}\\{1}', directory, 'key4.db')
                        if System.IO.File.Exists(firefoxCredentialFile4):
                            Console.WriteLine('  [*] Firefox credential file exists at {0}', firefoxCredentialFile4)
                            Console.WriteLine('      Run SharpWeb (https://github.com/djhohnstein/SharpWeb)\r\n')
        except ex as Exception:
            Console.WriteLine('  [X] Exception: {0}', ex.Message)

    public static def ParseFirefoxHistory(path as string, user as string):
        // parses a Firefox history file via regex
        if System.IO.Directory.Exists(path):
            directories as (string) = Directory.GetDirectories(path)
            for directory as string in directories:
                firefoxHistoryFile as string = String.Format('{0}\\{1}', directory, 'places.sqlite')

                Console.WriteLine('\r\n    History ({0}):\r\n', user)
                historyRegex = Regex('(http|ftp|https|file)://([\\w_-]+(?:(?:\\.[\\w_-]+)+))([\\w.,@?^=%&:/~+#-]*[\\w@?^=%&/~+#-])?')

                try:
                    using r = StreamReader(firefoxHistoryFile):
                        line as string
                        while (line = r.ReadLine()) is not null:
                            m as Match = historyRegex.Match(line)
                            if m.Success:
                                Console.WriteLine('      {0}', m.Groups[0].ToString().Trim())
                except exception as System.IO.IOException:
                    Console.WriteLine('\r\n    [x] IO exception, places.sqlite file likely in use (i.e. Firefox is likely running).', exception.Message)
                except exception as Exception:
                    Console.WriteLine('\r\n    [x] Exception: {0}', exception.Message)

    public static def TriageFirefox():

        userFirefoxBasePath as string
        userName as string
        try:
            if IsHighIntegrity():
                Console.WriteLine('\r\n\r\n=== Firefox (All Users) ===')
                userFolder as string = String.Format('{0}\\Users\\', Environment.GetEnvironmentVariable('SystemDrive'))
                dirs as (string) = Directory.GetDirectories(userFolder)
                for dir as string in dirs:
                    parts as (string) = dir.Split(char('\\'))
                    userName = parts[(parts.Length - 1)]
                    if not (((dir.EndsWith('Public') or dir.EndsWith('Default')) or dir.EndsWith('Default User')) or dir.EndsWith('All Users')):
                        userFirefoxBasePath = String.Format('{0}\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\', dir)
                        ParseFirefoxHistory(userFirefoxBasePath, userName)
            else:
                Console.WriteLine('\r\n\r\n=== Firefox (Current User) ===')
                userName = Environment.GetEnvironmentVariable('USERNAME')

                userFirefoxBasePath = String.Format('{0}\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\', System.Environment.GetEnvironmentVariable('USERPROFILE'))
                ParseFirefoxHistory(userFirefoxBasePath, userName)
        except ex as Exception:
            Console.WriteLine('  [X] Exception: {0}', ex.Message)


    public static def ListRecentRunCommands():
        // lists recently run commands via the RunMRU registry key

        recentCommands as Dictionary[of string, object]
        if IsHighIntegrity():
            Console.WriteLine('\r\n\r\n=== Recent Typed RUN Commands (All Users) ===')
            SIDs as (string) = Registry.Users.GetSubKeyNames()
            for SID as string in SIDs:
                if SID.StartsWith('S-1-5') and (not SID.EndsWith('_Classes')):
                    recentCommands = GetRegValues('HKU', String.Format('{0}\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU', SID))
                    if (recentCommands is not null) and (recentCommands.Count != 0):
                        Console.WriteLine('\r\n    {0} :', SID)
                        for kvp as KeyValuePair[of string, object] in recentCommands:
                            Console.WriteLine('      {0,-10} :  {1}', kvp.Key, kvp.Value)
        else:
            Console.WriteLine('\r\n\r\n=== Recent Typed RUN Commands (Current User) ===\r\n')

            recentCommands = GetRegValues('HKCU', 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU')
            if (recentCommands is not null) and (recentCommands.Count != 0):
                for kvp as KeyValuePair[of string, object] in recentCommands:
                    Console.WriteLine('    {0,-10} :  {1}', kvp.Key, kvp.Value)


    public static def ListPuttySessions():
        // extracts saved putty sessions and basic configs (via the registry)

        result as string
        keys as (string)
        subKeys as (string)
        if IsHighIntegrity():
            Console.WriteLine('\r\n\r\n=== Putty Saved Session Information (All Users) ===\r\n')
            SIDs as (string) = Registry.Users.GetSubKeyNames()
            for SID as string in SIDs:
                if SID.StartsWith('S-1-5') and (not SID.EndsWith('_Classes')):
                    subKeys = GetRegSubkeys('HKU', String.Format('{0}\\Software\\SimonTatham\\PuTTY\\Sessions\\', SID))
                    for sessionName as string in subKeys:
                        Console.WriteLine('    {0,-20}  :  {1}', 'User SID', SID)
                        Console.WriteLine('    {0,-20}  :  {1}', 'SessionName', sessionName)
                        keys = ('HostName', 'UserName', 'PublicKeyFile', 'PortForwardings', 'ConnectionSharing')
                        for key as string in keys:
                            result = GetRegValue('HKU', String.Format('{0}\\Software\\SimonTatham\\PuTTY\\Sessions\\{1}', SID, sessionName), key)
                            if not String.IsNullOrEmpty(result):
                                Console.WriteLine('    {0,-20}  :  {1}', key, result)
                        Console.WriteLine()
        else:
            Console.WriteLine('\r\n\r\n=== Putty Saved Session Information (Current User) ===\r\n')

            subKeys = GetRegSubkeys('HKCU', 'Software\\SimonTatham\\PuTTY\\Sessions\\')
            for sessionName as string in subKeys:
                Console.WriteLine('    {0,-20}  :  {1}', 'SessionName', sessionName)

                keys = ('HostName', 'UserName', 'PublicKeyFile', 'PortForwardings', 'ConnectionSharing')

                for key as string in keys:
                    result = GetRegValue('HKCU', String.Format('Software\\SimonTatham\\PuTTY\\Sessions\\{0}', sessionName), key)
                    if not String.IsNullOrEmpty(result):
                        Console.WriteLine('    {0,-20}  :  {1}', key, result)
                Console.WriteLine()


    public static def ListPuttySSHHostKeys():
        // extracts saved putty host keys (via the registry)

        hostKeys as Dictionary[of string, object]
        if IsHighIntegrity():
            Console.WriteLine('\r\n\r\n=== Putty SSH Host Hosts (All Users) ===\r\n')
            SIDs as (string) = Registry.Users.GetSubKeyNames()
            for SID as string in SIDs:
                if SID.StartsWith('S-1-5') and (not SID.EndsWith('_Classes')):
                    hostKeys = GetRegValues('HKU', String.Format('{0}\\Software\\SimonTatham\\PuTTY\\SshHostKeys\\', SID))
                    if (hostKeys is not null) and (hostKeys.Count != 0):
                        Console.WriteLine('    {0} :', SID)
                        for kvp as KeyValuePair[of string, object] in hostKeys:
                            Console.WriteLine('      {0,-10}', kvp.Key)
        else:
            Console.WriteLine('\r\n\r\n=== Putty SSH Host Key Recent Hosts (Current User) ===\r\n')

            hostKeys = GetRegValues('HKCU', 'Software\\SimonTatham\\PuTTY\\SshHostKeys\\')
            if (hostKeys is not null) and (hostKeys.Count != 0):
                for kvp as KeyValuePair[of string, object] in hostKeys:
                    Console.WriteLine('    {0,-10}', kvp.Key)

        //Console.WriteLine("\r\n\r\n=== Putty SSH Host Key Recent Hosts ===\r\n");

        //Dictionary<string, object> sessions = GetRegValues("HKCU", "Software\\SimonTatham\\PuTTY\\SshHostKeys\\");
        //if (sessions != null)
        //{
        //    foreach (KeyValuePair<string, object> kvp in sessions)
        //    {
        //        Console.WriteLine("    {0,-10}", kvp.Key);
        //    }
        //}


    public static def ListCloudCreds():
        // checks for various cloud credential files (AWS, Microsoft Azure, and Google Compute)
        // adapted from https://twitter.com/cmaddalena's SharpCloud project (https://github.com/chrismaddalena/SharpCloud/)

        size as long
        lastModified as DateTime
        lastAccessed as DateTime
        azureProfile as string
        azureTokens as string
        computeAccessTokensDb as string
        computeLegacyCreds as string
        computeCredsDb as string
        awsKeyFile as string
        try:
            if IsHighIntegrity():
                Console.WriteLine('\r\n\r\n=== Checking for Cloud Credentials (All Users) ===\r\n')
                userFolder as string = String.Format('{0}\\Users\\', Environment.GetEnvironmentVariable('SystemDrive'))
                dirs as (string) = Directory.GetDirectories(userFolder)
                for dir as string in dirs:
                    found = false
                    parts as (string) = dir.Split(char('\\'))
                    userName as string = parts[(parts.Length - 1)]
                    if not (((dir.EndsWith('Public') or dir.EndsWith('Default')) or dir.EndsWith('Default User')) or dir.EndsWith('All Users')):
                        awsKeyFile = String.Format('{0}\\.aws\\credentials', dir)
                        if System.IO.File.Exists(awsKeyFile):
                            lastAccessed = System.IO.File.GetLastAccessTime(awsKeyFile)
                            lastModified = System.IO.File.GetLastWriteTime(awsKeyFile)
                            size = System.IO.FileInfo(awsKeyFile).Length
                            Console.WriteLine('  [*] AWS key file exists at     : {0}', awsKeyFile)
                            Console.WriteLine('      Accessed                   : {0}', lastAccessed)
                            Console.WriteLine('      Modified                   : {0}', lastModified)
                            Console.WriteLine('      Size                       : {0}\r\n', size)
                            found = true
                        computeCredsDb = String.Format('{0}\\AppData\\Roaming\\gcloud\\credentials.db', dir)
                        if System.IO.File.Exists(computeCredsDb):
                            lastAccessed = System.IO.File.GetLastAccessTime(computeCredsDb)
                            lastModified = System.IO.File.GetLastWriteTime(computeCredsDb)
                            size = System.IO.FileInfo(computeCredsDb).Length
                            Console.WriteLine('  [*] Compute creds at           : {0}', computeCredsDb)
                            Console.WriteLine('      Accessed                   : {0}', lastAccessed)
                            Console.WriteLine('      Modified                   : {0}', lastModified)
                            Console.WriteLine('      Size                       : {0}\r\n', size)
                            found = true
                        computeLegacyCreds = String.Format('{0}\\AppData\\Roaming\\gcloud\\legacy_credentials', dir)
                        if System.IO.File.Exists(computeLegacyCreds):
                            lastAccessed = System.IO.File.GetLastAccessTime(computeLegacyCreds)
                            lastModified = System.IO.File.GetLastWriteTime(computeLegacyCreds)
                            size = System.IO.FileInfo(computeLegacyCreds).Length
                            Console.WriteLine('  [*] Compute legacy creds at    : {0}', computeLegacyCreds)
                            Console.WriteLine('      Accessed                   : {0}', lastAccessed)
                            Console.WriteLine('      Modified                   : {0}', lastModified)
                            Console.WriteLine('      Size                       : {0}\r\n', size)
                            found = true
                        computeAccessTokensDb = String.Format('{0}\\AppData\\Roaming\\gcloud\\access_tokens.db', dir)
                        if System.IO.File.Exists(computeAccessTokensDb):
                            lastAccessed = System.IO.File.GetLastAccessTime(computeAccessTokensDb)
                            lastModified = System.IO.File.GetLastWriteTime(computeAccessTokensDb)
                            size = System.IO.FileInfo(computeAccessTokensDb).Length
                            Console.WriteLine('  [*] Compute access tokens at   : {0}', computeAccessTokensDb)
                            Console.WriteLine('      Accessed                   : {0}', lastAccessed)
                            Console.WriteLine('      Modified                   : {0}', lastModified)
                            Console.WriteLine('      Size                       : {0}\r\n', size)
                            found = true
                        azureTokens = String.Format('{0}\\.azure\\accessTokens.json', dir)
                        if System.IO.File.Exists(azureTokens):
                            lastAccessed = System.IO.File.GetLastAccessTime(azureTokens)
                            lastModified = System.IO.File.GetLastWriteTime(azureTokens)
                            size = System.IO.FileInfo(azureTokens).Length
                            Console.WriteLine('  [*] Azure access tokens at     : {0}', azureTokens)
                            Console.WriteLine('      Accessed                   : {0}', lastAccessed)
                            Console.WriteLine('      Modified                   : {0}', lastModified)
                            Console.WriteLine('      Size                       : {0}\r\n', size)
                            found = true
                        azureProfile = String.Format('{0}\\.azure\\azureProfile.json', dir)
                        if System.IO.File.Exists(azureProfile):
                            lastAccessed = System.IO.File.GetLastAccessTime(azureProfile)
                            lastModified = System.IO.File.GetLastWriteTime(azureProfile)
                            size = System.IO.FileInfo(azureProfile).Length
                            Console.WriteLine('  [*] Azure profile at           : {0}', azureProfile)
                            Console.WriteLine('      Accessed                   : {0}', lastAccessed)
                            Console.WriteLine('      Modified                   : {0}', lastModified)
                            Console.WriteLine('      Size                       : {0}\r\n', size)
                            found = true
                        if found:
                            System.Console.WriteLine()
            else:
                Console.WriteLine('\r\n\r\n=== Checking for Cloud Credentials (Current User) ===\r\n')

                awsKeyFile = String.Format('{0}\\.aws\\credentials', System.Environment.GetEnvironmentVariable('USERPROFILE'))
                if System.IO.File.Exists(awsKeyFile):
                    lastAccessed = System.IO.File.GetLastAccessTime(awsKeyFile)
                    lastModified = System.IO.File.GetLastWriteTime(awsKeyFile)
                    size = System.IO.FileInfo(awsKeyFile).Length
                    Console.WriteLine('  [*] AWS key file exists at     : {0}', awsKeyFile)
                    Console.WriteLine('      Accessed                   : {0}', lastAccessed)
                    Console.WriteLine('      Modified                   : {0}', lastModified)
                    Console.WriteLine('      Size                       : {0}\r\n', size)
                computeCredsDb = String.Format('{0}\\AppData\\Roaming\\gcloud\\credentials.db', System.Environment.GetEnvironmentVariable('USERPROFILE'))
                if System.IO.File.Exists(computeCredsDb):
                    lastAccessed = System.IO.File.GetLastAccessTime(computeCredsDb)
                    lastModified = System.IO.File.GetLastWriteTime(computeCredsDb)
                    size = System.IO.FileInfo(computeCredsDb).Length
                    Console.WriteLine('  [*] Compute creds at           : {0}', computeCredsDb)
                    Console.WriteLine('      Accessed                   : {0}', lastAccessed)
                    Console.WriteLine('      Modified                   : {0}', lastModified)
                    Console.WriteLine('      Size                       : {0}\r\n', size)
                computeLegacyCreds = String.Format('{0}\\AppData\\Roaming\\gcloud\\legacy_credentials', System.Environment.GetEnvironmentVariable('USERPROFILE'))
                if System.IO.File.Exists(computeLegacyCreds):
                    lastAccessed = System.IO.File.GetLastAccessTime(computeLegacyCreds)
                    lastModified = System.IO.File.GetLastWriteTime(computeLegacyCreds)
                    size = System.IO.FileInfo(computeLegacyCreds).Length
                    Console.WriteLine('  [*] Compute legacy creds at    : {0}', computeLegacyCreds)
                    Console.WriteLine('      Accessed                   : {0}', lastAccessed)
                    Console.WriteLine('      Modified                   : {0}', lastModified)
                    Console.WriteLine('      Size                       : {0}\r\n', size)
                computeAccessTokensDb = String.Format('{0}\\AppData\\Roaming\\gcloud\\access_tokens.db', System.Environment.GetEnvironmentVariable('USERPROFILE'))
                if System.IO.File.Exists(computeAccessTokensDb):
                    lastAccessed = System.IO.File.GetLastAccessTime(computeAccessTokensDb)
                    lastModified = System.IO.File.GetLastWriteTime(computeAccessTokensDb)
                    size = System.IO.FileInfo(computeAccessTokensDb).Length
                    Console.WriteLine('  [*] Compute access tokens at   : {0}', computeAccessTokensDb)
                    Console.WriteLine('      Accessed                   : {0}', lastAccessed)
                    Console.WriteLine('      Modified                   : {0}', lastModified)
                    Console.WriteLine('      Size                       : {0}\r\n', size)
                azureTokens = String.Format('{0}\\.azure\\accessTokens.json', System.Environment.GetEnvironmentVariable('USERPROFILE'))
                if System.IO.File.Exists(azureTokens):
                    lastAccessed = System.IO.File.GetLastAccessTime(azureTokens)
                    lastModified = System.IO.File.GetLastWriteTime(azureTokens)
                    size = System.IO.FileInfo(azureTokens).Length
                    Console.WriteLine('  [*] Azure access tokens at     : {0}', azureTokens)
                    Console.WriteLine('      Accessed                   : {0}', lastAccessed)
                    Console.WriteLine('      Modified                   : {0}', lastModified)
                    Console.WriteLine('      Size                       : {0}\r\n', size)
                azureProfile = String.Format('{0}\\.azure\\azureProfile.json', System.Environment.GetEnvironmentVariable('USERPROFILE'))
                if System.IO.File.Exists(azureProfile):
                    lastAccessed = System.IO.File.GetLastAccessTime(azureProfile)
                    lastModified = System.IO.File.GetLastWriteTime(azureProfile)
                    size = System.IO.FileInfo(azureProfile).Length
                    Console.WriteLine('  [*] Azure profile at           : {0}', azureProfile)
                    Console.WriteLine('      Accessed                   : {0}', lastAccessed)
                    Console.WriteLine('      Modified                   : {0}', lastModified)
                    Console.WriteLine('      Size                       : {0}\r\n', size)
        except ex as Exception:
            Console.WriteLine('  [X] Exception: {0}', ex.Message)


    public static def ListRecentFiles():
        // parses recent file shortcuts via COM
        // WshShell COM object GUID
        // invoke the WshShell com object, creating a shortcut to then extract the TargetPath from
        TargetPath as Object
        shortcut as Object
        lastAccessed as DateTime
        recentFiles as (string)
        recentPath as string
        lastDays = 7
        if not FilterResults.filter:
            lastDays = 30
        startTime as DateTime = System.DateTime.Now.AddDays(-lastDays)
        try:
            shell as Type = Type.GetTypeFromCLSID(Guid('F935DC22-1CF0-11d0-ADB9-00C04FD58A0B'))
            shellObj as Object = Activator.CreateInstance(shell)
            if IsHighIntegrity():
                Console.WriteLine('\r\n\r\n=== Recently Accessed Files (All Users) Last {0} Days ===\r\n', lastDays)
                userFolder as string = String.Format('{0}\\Users\\', Environment.GetEnvironmentVariable('SystemDrive'))
                dirs as (string) = Directory.GetDirectories(userFolder)
                for dir as string in dirs:
                    parts as (string) = dir.Split(char('\\'))
                    userName as string = parts[(parts.Length - 1)]
                    if not (((dir.EndsWith('Public') or dir.EndsWith('Default')) or dir.EndsWith('Default User')) or dir.EndsWith('All Users')):
                        recentPath = String.Format('{0}\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\', dir)
                        try:
                            recentFiles = Directory.GetFiles(recentPath, '*.lnk', SearchOption.AllDirectories)
                            if recentFiles.Length != 0:
                                Console.WriteLine('   {0} :\r\n', userName)
                                for recentFile as string in recentFiles:
                                    lastAccessed = System.IO.File.GetLastAccessTime(recentFile)
                                    if lastAccessed > startTime:
                                        shortcut = shellObj.GetType().InvokeMember('CreateShortcut', BindingFlags.InvokeMethod, null, shellObj, (of object: recentFile))
                                        TargetPath = shortcut.GetType().InvokeMember('TargetPath', BindingFlags.GetProperty, null, shortcut, (of object: ,))

                                        if TargetPath.ToString().Trim() != '':
                                            Console.WriteLine('      Target:       {0,-10}', TargetPath.ToString())
                                            Console.WriteLine('          Accessed: {0}\r\n', lastAccessed)
                                        Marshal.ReleaseComObject(shortcut)
                                        shortcut = null
                        except :
                            pass
            else:
                Console.WriteLine('\r\n\r\n=== Recently Accessed Files (Current User) Last {0} Days ===\r\n', lastDays)

                recentPath = String.Format('{0}\\Microsoft\\Windows\\Recent\\', System.Environment.GetEnvironmentVariable('APPDATA'))

                recentFiles = Directory.GetFiles(recentPath, '*.lnk', SearchOption.AllDirectories)

                for recentFile as string in recentFiles:
                    // old method (needed interop dll)
                    //WshShell shell = new WshShell();
                    //IWshShortcut shortcut = (IWshShortcut)shell.CreateShortcut(recentFile);

                    lastAccessed = System.IO.File.GetLastAccessTime(recentFile)

                    if lastAccessed > startTime:
                        // invoke the WshShell com object, creating a shortcut to then extract the TargetPath from
                        shortcut = shellObj.GetType().InvokeMember('CreateShortcut', BindingFlags.InvokeMethod, null, shellObj, (of object: recentFile))
                        TargetPath = shortcut.GetType().InvokeMember('TargetPath', BindingFlags.GetProperty, null, shortcut, (of object: ,))
                        if TargetPath.ToString().Trim() != '':
                            Console.WriteLine('    Target:       {0,-10}', TargetPath.ToString())
                            Console.WriteLine('        Accessed: {0}\r\n', lastAccessed)
                        Marshal.ReleaseComObject(shortcut)
                        shortcut = null
            // release the WshShell COM object
            Marshal.ReleaseComObject(shellObj)
            shellObj = null
        except ex as Exception:
            Console.WriteLine('  [X] Exception: {0}', ex.Message)


    public static def ListInterestingFiles():
        // returns files (w/ modification dates) that match the given pattern below




        lastModified as DateTime
        lastAccessed as DateTime
        files as List[of string]
        searchPath as string
        patterns = '*pass *;*diagram*;*.pdf;*.vsd;*.doc;*docx;*.xls;*.xlsx;*.kdbx;*.key;KeePass.config'
        if IsHighIntegrity():
            Console.WriteLine('\r\n\r\n=== Interesting Files (All Users) ===\r\n')
            searchPath = String.Format('{0}\\Users\\', Environment.GetEnvironmentVariable('SystemDrive'))
            files = FindFiles(searchPath, patterns)
            for file as string in files:
                lastAccessed = System.IO.File.GetLastAccessTime(file)
                lastModified = System.IO.File.GetLastWriteTime(file)
                Console.WriteLine('    File:         {0}', file)
                Console.WriteLine('        Accessed: {0}', lastAccessed)
                Console.WriteLine('        Modified: {0}', lastModified)
        else:

            Console.WriteLine('\r\n\r\n=== Interesting Files (Current User) ===\r\n')

            searchPath = Environment.GetEnvironmentVariable('USERPROFILE')

            files = FindFiles(searchPath, patterns)

            for file as string in files:
                lastAccessed = System.IO.File.GetLastAccessTime(file)
                lastModified = System.IO.File.GetLastWriteTime(file)
                Console.WriteLine('    File:         {0}', file)
                Console.WriteLine('        Accessed: {0}', lastAccessed)
                Console.WriteLine('        Modified: {0}', lastModified)



    // misc checks
    public static def ListPatches():
        // lists current patches via WMI (win32_quickfixengineering)
        try:
            wmiData = ManagementObjectSearcher('root\\cimv2', 'SELECT * FROM win32_quickfixengineering')
            data as ManagementObjectCollection = wmiData.Get()

            Console.WriteLine('\r\n\r\n=== Installed Patches (via WMI) ===\r\n')
            Console.WriteLine('  HotFixID   InstalledOn    Description')

            for result as ManagementObject in data:
                Console.WriteLine(String.Format('  {0,-11}{1,-15}{2}', result['HotFixID'], result['InstalledOn'], result['Description']))
        except ex as Exception:
            Console.WriteLine('  [X] Exception: {0}', ex.Message)


    public static def ListRecycleBin():
        // lists recently deleted files (needs to be run from a user context!)

        // Reference: https://stackoverflow.com/questions/18071412/list-filenames-in-the-recyclebin-with-c-sharp-without-using-any-external-files
        Console.WriteLine('\r\n\r\n=== Recycle Bin Files Within the last 30 Days ===\r\n')

        lastDays = 30

        startTime = System.DateTime.Now.AddDays(-lastDays)

        // Shell COM object GUID
        shell as Type = Type.GetTypeFromCLSID(Guid('13709620-C279-11CE-A49E-444553540000'))
        shellObj as Object = Activator.CreateInstance(shell)

        // namespace for recycle bin == 10 - https://msdn.microsoft.com/en-us/library/windows/desktop/bb762494(v=vs.85).aspx
        recycle as Object = shellObj.GetType().InvokeMember('Namespace', BindingFlags.InvokeMethod, null, shellObj, (of object: 10))
        // grab all the deletes items
        items as Object = recycle.GetType().InvokeMember('Items', BindingFlags.InvokeMethod, null, recycle, null)
        // grab the number of deleted items
        count as Object = items.GetType().InvokeMember('Count', BindingFlags.GetProperty, null, items, null)
        deletedCount as int = Int32.Parse(count.ToString())
        for i in range(0, deletedCount):

        // iterate through each item
            // grab the specific deleted item
            item as Object = items.GetType().InvokeMember('Item', BindingFlags.InvokeMethod, null, items, (of object: i))
            DateDeleted as Object = item.GetType().InvokeMember('ExtendedProperty', BindingFlags.InvokeMethod, null, item, (of object: 'System.Recycle.DateDeleted'))
            modifiedDate as DateTime = DateTime.Parse(DateDeleted.ToString())
            if modifiedDate > startTime:
                // additional extended properties from https://blogs.msdn.microsoft.com/oldnewthing/20140421-00/?p=1183
                Name as Object = item.GetType().InvokeMember('Name', BindingFlags.GetProperty, null, item, null)
                Path as Object = item.GetType().InvokeMember('Path', BindingFlags.GetProperty, null, item, null)
                Size as Object = item.GetType().InvokeMember('Size', BindingFlags.GetProperty, null, item, null)
                DeletedFrom as Object = item.GetType().InvokeMember('ExtendedProperty', BindingFlags.InvokeMethod, null, item, (of object: 'System.Recycle.DeletedFrom'))
                Console.WriteLine('  Name           : {0}', Name)
                Console.WriteLine('  Path           : {0}', Path)
                Console.WriteLine('  Size           : {0}', Size)
                Console.WriteLine('  Deleted From   : {0}', DeletedFrom)
                Console.WriteLine('  Date Deleted   : {0}\r\n', DateDeleted)
            Marshal.ReleaseComObject(item)
            item = null
        Marshal.ReleaseComObject(recycle)
        recycle = null
        Marshal.ReleaseComObject(shellObj)
        shellObj = null



    // meta-functions for running various checks
    public static def SystemChecks():
        Console.WriteLine('\r\n=== Running System Triage Checks ===\r\n')
        ListBasicOSInfo()
        ListRebootSchedule()
        ListTokenGroupPrivs()
        ListUACSystemPolicies()
        ListPowerShellSettings()
        ListAuditSettings()
        ListWEFSettings()
        ListLSASettings()
        ListUserEnvVariables()
        ListSystemEnvVariables()
        ListUserFolders()
        ListNonstandardServices()
        ListInternetSettings()
        ListLapsSettings()
        ListLocalGroupMembers()
        ListMappedDrives()
        ListRDPSessions()
        ListWMIMappedDrives()
        ListNetworkShares()
        ListFirewallRules()
        ListAntiVirusWMI()
        ListInterestingProcesses()
        ListRegistryAutoLogon()
        ListRegistryAutoRuns()
        ListDNSCache()
        ListARPTable()
        ListAllTcpConnections()
        ListAllUdpConnections()
        ListNonstandardProcesses()

        // list patches and List4624Events/List4648Events if we're doing "full" collection
        if not FilterResults.filter:
            ListPatches()
            List4624Events()
            List4648Events()

        if IsHighIntegrity():
            Console.WriteLine('\r\n\r\n [*] In high integrity, performing elevated collection options.')
            ListSysmonConfig()


    public static def UserChecks():
        Console.WriteLine('\r\n=== Running User Triage Checks ===\r\n')

        if IsHighIntegrity():
            Console.WriteLine('\r\n [*] In high integrity, attempting triage for all users on the machine.')
            Console.WriteLine('\r\n     Current user : {0} - {1} ', WindowsIdentity.GetCurrent().Name, WindowsIdentity.GetCurrent().User)
        else:
            Console.WriteLine('\r\n [*] In medium integrity, attempting triage of current user.')
            Console.WriteLine('\r\n     Current user : {0} - {1} ', WindowsIdentity.GetCurrent().Name, WindowsIdentity.GetCurrent().User)

        CheckFirefox()
        CheckChrome()
        TriageIE()
        DumpVault()
        ListSavedRDPConnections()
        ListRecentRunCommands()
        ListPuttySessions()
        ListPuttySSHHostKeys()
        ListCloudCreds()
        ListRecentFiles()
        ListMasterKeys()
        ListCredFiles()
        ListRDCManFiles()

        if not FilterResults.filter:
            TriageChrome()
            TriageFirefox()
            ListInterestingFiles()


    private static def Usage():
        Console.WriteLine(' "SeatBelt.exe system" collects the following system data:\r\n')
        Console.WriteLine('\tBasicOSInfo           -   Basic OS info (i.e. architecture, OS version, etc.)')
        Console.WriteLine('\tRebootSchedule        -   Reboot schedule (last 15 days) based on event IDs 12 and 13')
        Console.WriteLine('\tTokenGroupPrivs       -   Current process/token privileges (e.g. SeDebugPrivilege/etc.)')
        Console.WriteLine('\tUACSystemPolicies     -   UAC system policies via the registry')
        Console.WriteLine('\tPowerShellSettings    -   PowerShell versions and security settings')
        Console.WriteLine('\tAuditSettings         -   Audit settings via the registry')
        Console.WriteLine('\tWEFSettings           -   Windows Event Forwarding (WEF) settings via the registry')
        Console.WriteLine('\tLSASettings           -   LSA settings (including auth packages)')
        Console.WriteLine('\tUserEnvVariables      -   Current user environment variables')
        Console.WriteLine('\tSystemEnvVariables    -   Current system environment variables')
        Console.WriteLine('\tUserFolders           -   Folders in C:\\Users\\')
        Console.WriteLine('\tNonstandardServices   -   Services with file info company names that don\'t contain \'Microsoft\'')
        Console.WriteLine('\tInternetSettings      -   Internet settings including proxy configs')
        Console.WriteLine('\tLapsSettings          -   LAPS settings, if installed')
        Console.WriteLine('\tLocalGroupMembers     -   Members of local admins, RDP, and DCOM')
        Console.WriteLine('\tMappedDrives          -   Mapped drives')
        Console.WriteLine('\tRDPSessions           -   Current incoming RDP sessions')
        Console.WriteLine('\tWMIMappedDrives       -   Mapped drives via WMI')
        Console.WriteLine('\tNetworkShares         -   Network shares')
        Console.WriteLine('\tFirewallRules         -   Deny firewall rules, "full" dumps all')
        Console.WriteLine('\tAntiVirusWMI          -   Registered antivirus (via WMI)')
        Console.WriteLine('\tInterestingProcesses  -   "Interesting" processes- defensive products and admin tools')
        Console.WriteLine('\tRegistryAutoRuns      -   Registry autoruns')
        Console.WriteLine('\tRegistryAutoLogon     -   Registry autologon information')
        Console.WriteLine('\tDNSCache              -   DNS cache entries (via WMI)')
        Console.WriteLine('\tARPTable              -   Lists the current ARP table and adapter information (equivalent to arp -a)')
        Console.WriteLine('\tAllTcpConnections     -   Lists current TCP connections and associated processes')
        Console.WriteLine('\tAllUdpConnections     -   Lists current UDP connections and associated processes')
        Console.WriteLine('\tNonstandardProcesses  -   Running processeswith file info company names that don\'t contain \'Microsoft\'')
        Console.WriteLine('\t *  If the user is in high integrity, the following additional actions are run:')
        Console.WriteLine('\tSysmonConfig          -   Sysmon configuration from the registry')

        Console.WriteLine('\r\n\r\n "SeatBelt.exe user" collects the following user data:\r\n')
        Console.WriteLine('\tSavedRDPConnections   -   Saved RDP connections')
        Console.WriteLine('\tTriageIE              -   Internet Explorer bookmarks and history  (last 7 days)')
        Console.WriteLine('\tDumpVault             -   Dump saved credentials in Windows Vault (i.e. logins from Internet Explorer and Edge), from SharpWeb')
        Console.WriteLine('\tRecentRunCommands     -   Recent "run" commands')
        Console.WriteLine('\tPuttySessions         -   Interesting settings from any saved Putty configurations')
        Console.WriteLine('\tPuttySSHHostKeys      -   Saved putty SSH host keys')
        Console.WriteLine('\tCloudCreds            -   AWS/Google/Azure cloud credential files')
        Console.WriteLine('\tRecentFiles           -   Parsed "recent files" shortcuts  (last 7 days)')
        Console.WriteLine('\tMasterKeys            -   List DPAPI master keys')
        Console.WriteLine('\tCredFiles             -   List Windows credential DPAPI blobs')
        Console.WriteLine('\tRDCManFiles           -   List Windows Remote Desktop Connection Manager settings files')
        Console.WriteLine('\t *  If the user is in high integrity, this data is collected for ALL users instead of just the current user')

        Console.WriteLine('\r\n\r\n Non-default options:\r\n')
        Console.WriteLine('\tCurrentDomainGroups   -   The current user\'s local and domain groups')
        Console.WriteLine('\tPatches               -   Installed patches via WMI (takes a bit on some systems)')
        Console.WriteLine('\tLogonSessions         -   User logon session data')
        Console.WriteLine('\tKerberosTGTData       -   ALL TEH TGTZ!')
        Console.WriteLine('\tInterestingFiles      -   "Interesting" files matching various patterns in the user\'s folder')
        Console.WriteLine('\tIETabs                -   Open Internet Explorer tabs')
        Console.WriteLine('\tTriageChrome          -   Chrome bookmarks and history')
        Console.WriteLine('\tTriageFirefox         -   Firefox history (no bookmarks)')
        Console.WriteLine('\tRecycleBin            -   Items in the Recycle Bin deleted in the last 30 days - only works from a user context!')
        Console.WriteLine('\t4624Events            -   4624 logon events from the security event log')
        Console.WriteLine('\t4648Events            -   4648 explicit logon events from the security event log (runas or outbound RDP)')
        Console.WriteLine('\tKerberosTickets       -   List Kerberos tickets. If elevated, grouped by all logon sessions.')

        Console.WriteLine('\r\n\r\n "SeatBelt.exe all" will run ALL enumeration checks, can be combined with "full".\r\n')
        Console.WriteLine('\r\n "SeatBelt.exe [CheckName] full" will prevent any filtering and will return complete results.\r\n')
        Console.WriteLine('\r\n "SeatBelt.exe [CheckName] [CheckName2] ..." will run one or more specified checks only (case-sensitive naming!)\r\n')


    public static def Main(args as (string)):
        PrintLogo()

        watch = System.Diagnostics.Stopwatch.StartNew()

        if args.Length != 0:
            for arg as string in args:
                if string.Equals(arg, 'full', StringComparison.CurrentCultureIgnoreCase):
                    FilterResults.filter = false

            for arg as string in args:
                if string.Equals(arg, 'full', StringComparison.CurrentCultureIgnoreCase):
                    FilterResults.filter = false
                    if args.Length == 1:
                        // if "full" is the only argument, run System and User triage
                        SystemChecks()
                        ListKerberosTickets()
                        UserChecks()
                        ListIETabs()
                        ListPatches()
                        ListRecycleBin()

                        watch.Stop()
                        Console.WriteLine('\r\n\r\n[*] Completed All Safety Checks with no filtering in {0} seconds\r\n', (watch.ElapsedMilliseconds / 1000))
                        return
                if string.Equals(arg, 'all', StringComparison.CurrentCultureIgnoreCase):
                    SystemChecks()
                    ListKerberosTickets()
                    UserChecks()
                    ListIETabs()
                    ListPatches()
                    TriageChrome()
                    TriageFirefox()
                    ListRecycleBin()
                    ListInterestingFiles()

                    watch.Stop()
                    Console.WriteLine('\r\n\r\n[*] Completed All Safety Checks in {0} seconds\r\n', (watch.ElapsedMilliseconds / 1000))
                    return

            for arg as string in args:
                if string.Equals(arg, 'full', StringComparison.CurrentCultureIgnoreCase):
                    pass
                elif string.Equals(arg, 'system', StringComparison.CurrentCultureIgnoreCase):
                    SystemChecks()
                elif string.Equals(arg, 'user', StringComparison.CurrentCultureIgnoreCase):
                    UserChecks()
                else:
                    type as Type = typeof(SeatBelt)

                    info as MethodInfo = null

                    // try to grab the function name via reflection
                    if Regex.IsMatch(arg, '^Triage.*'):
                        // if TriageX(), all good
                        info = type.GetMethod(arg)
                    elif Regex.IsMatch(arg, '^Dump.*'):
                        // if DumpX, all good
                        info = type.GetMethod(arg)
                    else:
                        // build List<name>()
                        info = type.GetMethod(String.Format('List{0}', arg))

                    if info is null:
                        Console.WriteLine('[X] Check "{0}" not found!', arg)
                    else:
                        info.Invoke(null, (of object: ,))
        else:
            Usage()
            return

        watch.Stop()
        Console.WriteLine('\r\n\r\n[*] Completed Safety Checks in {0} seconds\r\n', (watch.ElapsedMilliseconds / 1000))


public static def Main():
    SeatBelt.Main("ARGS_GO_HERE".Split())
