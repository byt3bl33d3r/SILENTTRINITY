import System
import System.IO
import System.Diagnostics
import System.Security.Principal
import System.Runtime.InteropServices

public static def Start(job as duck):
    file = `SRCFILE_PATH`

    print "[*] Downloading $(file) ... "
    job.Upload(file)
