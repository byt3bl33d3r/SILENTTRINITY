import System
import System.IO
import System.Runtime.InteropServices
import System.Drawing
import System.Drawing.Imaging
import System.Management from System.Management
import System.Text


enum RasterOperation:
    SRC_COPY = 0x00CC0020

[DllImport('Gdi32.dll')]
def BitBlt(hdcDest as IntPtr, nXDest as int, nYDest as int, nWidth as int, nHeight as int, hdcSrc as IntPtr, nXSrc as int, nYSrc as int, rasterOperation as RasterOperation) as int:
    pass

[DllImport('User32.dll')]
def GetDC(hwnd as IntPtr) as IntPtr:
    pass

[DllImport('User32.dll')]
def ReleaseDC(hwnd as IntPtr, hdc as IntPtr) as int:
    pass

def GetBounds() as Rectangle:
    width as int = 0
    height as int = 0
    managementScope = ManagementScope()
    managementScope.Connect()
    query = ObjectQuery('SELECT CurrentHorizontalResolution, CurrentVerticalResolution FROM Win32_VideoController')
    for record as ManagementObject in ManagementObjectSearcher(managementScope, query).Get() :
        width = record['CurrentHorizontalResolution']
        height = record['CurrentVerticalResolution']
    bounds as Rectangle = Rectangle()
    bounds.Width = width
    bounds.Height = height

    return bounds

def takeScreenshot() as string:
    try:
        bounds as Rectangle = GetBounds()
        hdc as IntPtr = GetDC(IntPtr.Zero)
        bitmap as Bitmap = Bitmap(bounds.Width, bounds.Height, PixelFormat.Format16bppRgb565)
        
        graphics = Graphics.FromImage(bitmap) as Graphics
        dstHdc as IntPtr = graphics.GetHdc()
        BitBlt(dstHdc, 0, 0, bounds.Width, bounds.Height, hdc, 0, 0, RasterOperation.SRC_COPY)
        graphics.ReleaseHdc(dstHdc)
        ReleaseDC(IntPtr.Zero, hdc)
        
        stream = MemoryStream() as MemoryStream
        bitmap.Save(stream, ImageFormat.Jpeg);
        
        return Convert.ToBase64String(stream.ToArray()) as string
    except e:
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(e.ToString()))

[STAThread]
def Main(argv as (string)):
    output = takeScreenshot()
