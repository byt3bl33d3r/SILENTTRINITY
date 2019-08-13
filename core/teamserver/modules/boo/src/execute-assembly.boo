import System
import System.Reflection
import System.Text
import System.IO


public static def Main():
    encoded_assembly = "ASSEMBLY_BASE64"

    assembly = Assembly.Load(Convert.FromBase64String(encoded_assembly))
    args = Array[Object]([Array[String](["ARGS"])])

    assembly.EntryPoint.Invoke(null, args)
