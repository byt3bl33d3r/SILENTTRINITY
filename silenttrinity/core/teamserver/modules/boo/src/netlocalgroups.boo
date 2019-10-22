/*
    This module is inspired from SharpSploit (https://github.com/cobbr/SharpSploit)
*/
import System
import System.Net
import System.Runtime.InteropServices


[DllImport("netapi32.dll")]
def NetLocalGroupEnum(
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
public struct LOCALGROUP_USERS_INFO_1:
    [MarshalAs(UnmanagedType.LPWStr)] public name as string
    [MarshalAs(UnmanagedType.LPWStr)] public comment as string


public static def Main():
    computerName = "COMPUTER_NAME"

    if not computerName:
        print "\r\n[*] Retrieving local groups of machine " + Dns.GetHostName() + " (localhost)\r\n"
    else:
        print "\r\n[*] Retrieving local groups of machine " + computerName + "\r\n"

    QueryLevel as int = 1
    PtrInfo as IntPtr
    EntriesRead as int = 0
    TotalRead as int = 0
    ResumeHandle as int = 0
    Result as int = NetLocalGroupEnum(computerName, QueryLevel, PtrInfo, -1, EntriesRead, TotalRead, ResumeHandle)
    Offset as long = PtrInfo.ToInt64()
    if (Result == 0 and Offset > 0):
        increment as int = Marshal.SizeOf(typeof(LOCALGROUP_USERS_INFO_1))
        for i in range(0, EntriesRead):
            NextIntPtr as IntPtr = IntPtr(Offset)
            Info as LOCALGROUP_USERS_INFO_1 = Marshal.PtrToStructure(NextIntPtr, typeof(LOCALGROUP_USERS_INFO_1))
            Offset = NextIntPtr.ToInt64()
            Offset += increment
            print "GroupName:  " + Info.name
            print "Comment:    " + Info.comment + "\r\n"
        NetApiBufferFree(PtrInfo)
    else:
        print "Error: " + System.ComponentModel.Win32Exception(Result).Message
