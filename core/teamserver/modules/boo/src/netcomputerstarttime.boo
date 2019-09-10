/*
    This module is inspired from PowerView (https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)
*/
import System
import System.Net
import System.Runtime.InteropServices

[DllImport("netapi32.dll")]
def NetStatisticsGet(
    [MarshalAs(UnmanagedType.LPWStr)] servername as string,
    [MarshalAs(UnmanagedType.LPWStr)] service as string,
    level as int,
    options as int,
    ref bufptr as IntPtr
) as int:
    pass

[DllImport("netapi32.dll")]
def NetApiBufferFree(Buffer as IntPtr) as int:
    pass

[StructLayout(LayoutKind.Sequential)]
public struct STAT_WORKSTATION_0:
    public StatisticsStartTime as long
    public BytesReceived as long
    public SmbsReceived as long
    public PagingReadBytesRequested as long
    public NonPagingReadBytesRequested as long
    public CacheReadBytesRequested as long
    public NetworkReadBytesRequested as long
    public BytesTransmitted as int
    public SmbsTransmitted as int
    public PagingWriteBytesRequested as int
    public NonPagingWriteBytesRequested as int
    public CacheWriteBytesRequested as int
    public NetworkWriteBytesRequested as int
    public InitiallyFailedOperations as int
    public FailedCompletionOperations as int
    public ReadOperations as int
    public RandomReadOperations as int
    public ReadSmbs as int
    public LargeReadSmbs as int
    public SmallReadSmbs as int
    public WriteOperations as int
    public RandomWriteOperations as int
    public WriteSmbs as int
    public LargeWriteSmbs as int
    public SmallWriteSmbs as int
    public RawReadsDenied as int
    public RawWritesDenied as int
    public NetworkErrors as int
    public Sessions as int
    public FailedSessions as int
    public Reconnects as int
    public CoreConnects as int
    public Lanman20Connects as int
    public Lanman21Connects as int
    public LanmanNtConnects as int
    public ServerDisconnects as int
    public HungSessions as int
    public UseCount as int
    public FailedUseCount as int
    public CurrentCommands as int



public static def Main():
    computerName = "COMPUTER_NAME"

    if not computerName:
        print "\r\n[*] Retrieving start time of machine " + Dns.GetHostName() + " (localhost)\r\n"
    else:
        print "\r\n[*] Retrieving start time of machine " + computerName + "\r\n"

    QueryLevel as int = 0
    PtrInfo as IntPtr
    ServiceName = "LanmanWorkstation"

    Result as int = NetStatisticsGet(computerName,ServiceName,QueryLevel,0,PtrInfo)

    if (Result == 0):
        Info as STAT_WORKSTATION_0 = Marshal.PtrToStructure(PtrInfo, typeof(STAT_WORKSTATION_0))

        dateTime as DateTime = DateTime.MinValue
        dateTime = DateTime.FromFileTime(Info.StatisticsStartTime)
        value as string = dateTime.ToString()

        print "start time:  " + value + "\r\n"
    else:
        print "Error: " + System.ComponentModel.Win32Exception(Result).Message
