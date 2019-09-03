/*
    This module is inspired from SharpSploit (https://github.com/cobbr/SharpSploit)
*/
import System
import System.Net
import System.Runtime.InteropServices
import System.Security.Principal
import System.DirectoryServices
import System.Linq
import System.Text.RegularExpressions


[DllImport("netapi32.dll")]
def NetLocalGroupGetMembers(
    [MarshalAs(UnmanagedType.LPWStr)] servername as string,
    [MarshalAs(UnmanagedType.LPWStr)] localgroupname as string,
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


[DllImport("advapi32.dll", CharSet: CharSet.Auto, SetLastError: true)]
def ConvertSidToStringSid(Sid as IntPtr, ref StringSid as IntPtr) as bool:
    pass


[DllImport("kernel32.dll", SetLastError: true)]
def LocalFree(hMem as IntPtr) as IntPtr:
    pass


[StructLayout(LayoutKind.Sequential, CharSet: CharSet.Unicode)]
public struct LOCALGROUP_MEMBERS_INFO_2:
    public lgrmi2_sid as IntPtr
    public lgrmi2_sidusage as int
    [MarshalAs(UnmanagedType.LPWStr)] public lgrmi2_domainandname as string


public static def GetComputerSid(ComputerName as string) as string:
    if not ComputerName:
        ComputerName = "127.0.0.1"
    for d in DirectoryEntry(string.Format("WinNT://{0},Computer", ComputerName)).Children:
      return SecurityIdentifier(d.InvokeGet("objectSID"), 0).AccountDomainSid.ToString()


public static def Main():
    computerName = "COMPUTER_NAME"
    groupName = "GROUP_NAME"

    if not computerName:
        print "\r\n[*] Retrieving group members of local group " + groupName + " on machine " + Dns.GetHostName() + " (localhost)\r\n"
    else:
        print "\r\n[*] Retrieving group members of local group " + groupName + " on machine " + computerName + "\r\n"

    QueryLevel as int = 2
    PtrInfo as IntPtr
    EntriesRead as int = 0
    TotalRead as int = 0
    ResumeHandle as int = 0
    Result as int = NetLocalGroupGetMembers(computerName, groupName, QueryLevel, PtrInfo, -1, EntriesRead, TotalRead, ResumeHandle)
    Offset as long = PtrInfo.ToInt64()
    localUserRegex as Regex = Regex(".*-500")
    localUserRegex2 as Regex = Regex(".*-501")
    if (Result == 0 and Offset > 0):
        increment as int = Marshal.SizeOf(typeof(LOCALGROUP_MEMBERS_INFO_2))
        for i in range(0, EntriesRead):
            NextIntPtr as IntPtr = IntPtr(Offset)
            Info as LOCALGROUP_MEMBERS_INFO_2 = Marshal.PtrToStructure(NextIntPtr, typeof(LOCALGROUP_MEMBERS_INFO_2))
            Offset = NextIntPtr.ToInt64()
            Offset += increment

            ptrSid as IntPtr
            Result2 as bool = ConvertSidToStringSid(Info.lgrmi2_sid, ptrSid)

            if (not Result2):
                LastError as int = Marshal.GetLastWin32Error()
                print "Error: " + System.ComponentModel.Win32Exception(LastError).Message
            else:
                SidString as string = ""
                try:
                    SidString = Marshal.PtrToStringAuto(ptrSid)
                ensure:
                    LocalFree(ptrSid)

                print "MemberName:   " + Info.lgrmi2_domainandname
                print "SID:          " + SidString
                print "IsGroup:      " + (Info.lgrmi2_sidusage == 2).ToString()
                if SidString.Contains(GetComputerSid(computerName)):
                    print "IsDomain:     False\r\n"
                else:
                    print "IsDomain:     True\r\n"

        NetApiBufferFree(PtrInfo)
    else:
        print "Error: " + System.ComponentModel.Win32Exception(Result).Message
