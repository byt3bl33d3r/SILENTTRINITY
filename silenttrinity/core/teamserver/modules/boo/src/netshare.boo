/*
    This module is inspired from PowerView (https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)
*/
import System
import System.Net
import System.Runtime.InteropServices


[DllImport("netapi32.dll")]
def NetShareEnum(
    [MarshalAs(UnmanagedType.LPWStr)] servername as string,
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


[StructLayout(LayoutKind.Sequential)]
public struct SHARE_INFO_1:
    [MarshalAs(UnmanagedType.LPWStr)] public netname as string
    public type as int
    [MarshalAs(UnmanagedType.LPWStr)] public remark as string


public static def Main():
    computerName = "COMPUTER_NAME"

    if not computerName:
        print "\r\n[*] Retrieving shares of machine " + Dns.GetHostName() + " (localhost)\r\n"
    else:
        print "\r\n[*] Retrieving shares of machine " + computerName + "\r\n"

    QueryLevel as int = 1
    PtrInfo as IntPtr
    EntriesRead as int = 0
    TotalRead as int = 0
    ResumeHandle as int = 0

    Result as int = NetShareEnum(computerName, QueryLevel, PtrInfo, -1, EntriesRead, TotalRead, ResumeHandle)

    Offset as long = PtrInfo.ToInt64()
    if (Result == 0 and Offset > 0):
        increment as int = Marshal.SizeOf(typeof(SHARE_INFO_1))
        for i in range(0, EntriesRead):
            NextIntPtr as IntPtr = IntPtr(Offset)
            Info as SHARE_INFO_1 = Marshal.PtrToStructure(NextIntPtr, typeof(SHARE_INFO_1))
            Offset = NextIntPtr.ToInt64()
            Offset += increment
            print "netname:  " + Info.netname
            print "remark:   " + Info.remark + "\r\n"
        NetApiBufferFree(PtrInfo)
    else:
        print "Error: " + System.ComponentModel.Win32Exception(Result).Message
