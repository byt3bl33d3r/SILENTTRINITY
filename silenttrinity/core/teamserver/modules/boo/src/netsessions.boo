/*
    This module is inspired from SharpSploit (https://github.com/cobbr/SharpSploit)
*/
import System
import System.Net
import System.Runtime.InteropServices
import System.Text


[DllImport("netapi32.dll", SetLastError: true)]
def NetSessionEnum(
    [In, MarshalAs(UnmanagedType.LPWStr)] ServerName as string,
    [In, MarshalAs(UnmanagedType.LPWStr)] UncClientName as string,
    [In, MarshalAs(UnmanagedType.LPWStr)] UserName as string,
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
public struct SESSION_INFO_10:
    public sesi10_cname as string
    public sesi10_username as string
    public sesi10_time as int
    public sesi10_idle_time as int


public static def GetNetSession(computerIP as string):
    QueryLevel as int = 10
    PtrInfo as IntPtr
    PtrInfo = IntPtr.Zero
    EntriesRead as int = 0
    TotalRead as int = 0
    ResumeHandle as int = 0
    Result as int
    Result = NetSessionEnum(computerIP, null, null, QueryLevel, PtrInfo, -1, EntriesRead, TotalRead, ResumeHandle)
    Offset as long = PtrInfo.ToInt64()
    if (Result == 0 and Offset > 0):
        increment as int = Marshal.SizeOf(typeof(SESSION_INFO_10))
        for i in range(0, EntriesRead):
            NextIntPtr as IntPtr = IntPtr(Offset)
            Info as SESSION_INFO_10 = Marshal.PtrToStructure(NextIntPtr, typeof(SESSION_INFO_10))
            Offset = NextIntPtr.ToInt64()
            Offset += increment
            print "CName:        " + Info.sesi10_cname
            print "UserName:     " + Info.sesi10_username
            print "Time:         " + Info.sesi10_time
            print "IdleTime:     " + Info.sesi10_idle_time
            print "ComputerName: " + Dns.GetHostByAddress(computerIP).HostName + " (" + computerIP +") " + "\r\n"
        NetApiBufferFree(PtrInfo)
    else:
        print "Error: " + System.ComponentModel.Win32Exception(Result).Message


public static def Main():
    computerName = "COMPUTER_NAME"

    if not computerName:
        print "\r\n[*] Retrieving logged on users of machine " + Dns.GetHostName() + " (localhost)\r\n"
        GetNetSession("127.0.0.1")
    else:
        print "\r\n[*] Retrieving logged on users of machine " + computerName + "\r\n"
        iphost as IPHostEntry = Dns.Resolve(computerName)
        addresses as (IPAddress) = iphost.AddressList
        // get each ip address
        for address as IPAddress in addresses:
            GetNetSession(address.ToString())
