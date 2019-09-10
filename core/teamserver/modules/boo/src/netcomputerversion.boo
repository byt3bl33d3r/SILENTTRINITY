/*
    This module is inspired from PowerView (https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)
*/
import System
import System.Net
import System.Runtime.InteropServices


[DllImport("netapi32.dll")]
def NetWkstaGetInfo(
    [MarshalAs(UnmanagedType.LPWStr)] servername as string,
    level as int,
    ref bufptr as IntPtr
) as int:
    pass

[DllImport("netapi32.dll")]
def NetApiBufferFree(Buffer as IntPtr) as int:
    pass

[StructLayout(LayoutKind.Sequential)]
public struct WKSTA_INFO_100:
    public platform_id as int
    [MarshalAs(UnmanagedType.LPWStr)] public computername as string
    [MarshalAs(UnmanagedType.LPWStr)] public langroup as string
    public ver_major as int
    public ver_minor as int

public static def Main():
    computerName = "COMPUTER_NAME"

    if not computerName:
        print "\r\n[*] Retrieving OS version of machine " + Dns.GetHostName() + " (localhost)\r\n"
    else:
        print "\r\n[*] Retrieving OS version of machine " + computerName + "\r\n"

    QueryLevel as int = 100
    PtrInfo as IntPtr

    Result as int = NetWkstaGetInfo(computerName, QueryLevel, PtrInfo)

    if (Result == 0):
        Info as WKSTA_INFO_100 = Marshal.PtrToStructure(PtrInfo, typeof(WKSTA_INFO_100))
        print "platform_id:  " + Info.platform_id
        print "computername:  " + Info.computername
        print "langroup:  " + Info.langroup
        print "ver_major:  " + Info.ver_major
        print "ver_minor:   " + Info.ver_minor + "\r\n"
    else:
        print "Error: " + System.ComponentModel.Win32Exception(Result).Message
