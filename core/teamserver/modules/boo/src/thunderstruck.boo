import System
import System.Runtime.InteropServices
import System.Threading



[StructLayout(LayoutKind.Sequential)]
public struct KEYBDINPUT:
    wVk as ushort 
    wScan as ushort 
    dwFlags as uint 
    time as uint
    dwExtraInfo as IntPtr


[StructLayout(LayoutKind.Explicit)]
struct InputUnion:
    [FieldOffset(0)]
    public mi as MOUSEINPUT
    [FieldOffset(0)]
    public ki as KEYBDINPUT
    [FieldOffset(0)]
    public hi as HARDWAREINPUT

[StructLayout(LayoutKind.Sequential)]
struct MOUSEINPUT:
    public dx as int
    public dy as int
    public mouseData as uint 
    public dwFlags as uint 
    public ime as uint 
    public dwExtraInfo as IntPtr


[StructLayout(LayoutKind.Sequential)]
struct HARDWAREINPUT:
    public uMsg as uint 
    public wParamL as ushort 
    public wParamH as ushort 

[StructLayout(LayoutKind.Sequential)]
public struct INPUT:
    public Type as uint
    public U as InputUnion


[DllImport("user32.dll", SetLastError: true)]
public def SendInput(nInputs as uint, [MarshalAs(UnmanagedType.LPArray), In]  pInputs as (INPUT), cbSize as int) as uint:
    pass



def crankItToEleven():
    KEYEVENTF_EXTKEY as uint = 0x0001
    KEYEVENTF_KEYUP as uint = 0x0002
    VOLUME_UP_KEY as ushort = 0xAF

    volumeUPInputs as INPUT
    volumeUPInputs.Type = 1
    volumeUPInputs.U.ki.wVk = VOLUME_UP_KEY
    volumeUPInputs.U.ki.wScan  = 0
    volumeUPInputs.U.ki.dwExtraInfo = IntPtr.Zero

    input as (INPUT) = array(INPUT,100)

    //usually volume up key increments volume by 2. So Only need to send it 50 times
    for i in range(0,100,2):
        volumeUPInputs.U.ki.dwFlags = KEYEVENTF_EXTKEY
        input[i] = volumeUPInputs
        volumeUPInputs.U.ki.dwFlags = KEYEVENTF_EXTKEY | KEYEVENTF_KEYUP
        input[i+1] = volumeUPInputs
    
    SendInput(input.Length cast uint, input, Marshal.SizeOf(typeof(INPUT)))


public static def Main():
    
    site = "SITE"
    ComType as Type
    ComObject as object
    ComType = Type.GetTypeFromProgID("InternetExplorer.Application")
    ComObject = Activator.CreateInstance(ComType)
    ComObject.GetType().InvokeMember("Visible", System.Reflection.BindingFlags.SetProperty, null, ComObject, (false,))
    ComObject.GetType().InvokeMember("Navigate", System.Reflection.BindingFlags.InvokeMethod, null, ComObject, (site,))
    
    Thread.Sleep(5000)


    //Every <MILS> seconds for <MINS> minutes CRANK IT TO 11!!!
    startTime = DateTime.UtcNow
    while(DateTime.UtcNow - startTime < TimeSpan.FromMinutes(MINS)):
        crankItToEleven()
        Thread.Sleep(MILS)

    print "You've been.....THUNDERSTRUCK!"