/*
    This module is inspired from SharpSploit (https://github.com/cobbr/SharpSploit)
*/
import System
import System.Net
import System.Runtime.InteropServices


[DllImport("netapi32.dll", CharSet: CharSet.Unicode, SetLastError: true)]
def NetWkstaUserEnum(
    servername as string,
    level as int,
    ref bufptr as IntPtr,
    prefmaxlen as int,
    ref entriesread as int,
    ref totalentries as int,
    ref resume_handle as int
) as int:
    pass


[DllImport("netapi32.dll")]
def NetApiBufferFree(Buffer as IntPtr) as int:
    pass


[StructLayout(LayoutKind.Sequential, CharSet: CharSet.Unicode)]
public struct WKSTA_USER_INFO_1:
    public wkui1_username as string
    public wkui1_logon_domain as string
    public wkui1_oth_domains as string
    public wkui1_logon_server as string


public static def Main():
    computerName = "COMPUTER_NAME"

    if not computerName:
        print "\r\n[*] Retrieving logged on users of machine " + Dns.GetHostName() + " (localhost)\r\n"
    else:
        print "\r\n[*] Retrieving logged on users of machine " + computerName + "\r\n"

    QueryLevel as int = 1
    PtrInfo as IntPtr
    EntriesRead as int = 0
    TotalRead as int = 0
    ResumeHandle as int = 0
    Result as int = NetWkstaUserEnum(computerName, QueryLevel, PtrInfo, -1, EntriesRead, TotalRead, ResumeHandle)
    Offset as long = PtrInfo.ToInt64()
    if (Result == 0 and Offset > 0):
        increment as int = Marshal.SizeOf(typeof(WKSTA_USER_INFO_1))
        for i in range(0, EntriesRead):
            NextIntPtr as IntPtr = IntPtr(Offset)
            Info as WKSTA_USER_INFO_1 = Marshal.PtrToStructure(NextIntPtr, typeof(WKSTA_USER_INFO_1))
            Offset = NextIntPtr.ToInt64()
            Offset += increment
            //TODO: Remove machine accounts?
            print "UserName:       " + Info.wkui1_username
            print "LogonDomain:    " + Info.wkui1_logon_domain
            print "AuthDomains:    " + Info.wkui1_oth_domains
            print "LogonServer:    " + Info.wkui1_logon_server + "\r\n"
        NetApiBufferFree(PtrInfo)
    else:
        print "Error: " + System.ComponentModel.Win32Exception(Result).Message
