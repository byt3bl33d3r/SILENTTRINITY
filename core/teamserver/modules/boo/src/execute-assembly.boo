import System
import System.Reflection
import System.IO


public static def Main():
    encodedCompressedAssembly = "B64_ENCODED_COMPRESSED_ASSEMBLY"
    deflatedStream = Compression.DeflateStream(
        MemoryStream(
            Convert.FromBase64String(encodedCompressedAssembly)
            ),
        Compression.CompressionMode.Decompress
    )

    uncompressedFileBytes as (byte) = array(byte, DECOMPRESSED_ASSEMBLY_LENGTH)
    deflatedStream.Read(uncompressedFileBytes, 0, DECOMPRESSED_ASSEMBLY_LENGTH)

    assembly = Assembly.Load(uncompressedFileBytes)
    args as (string) ASSEMBLY_ARGS
    assembly.EntryPoint.Invoke(null, (of object: (args)))
