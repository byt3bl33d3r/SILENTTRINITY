import System
import System.IO
import System.IO.Compression

public static def Main():
    EncodedString = "ENCODEDTEXT"
    Destination = "DESTINATION"

    print "[*] Destionation: $(Destination)"
    rawdata as (byte) = Convert.FromBase64String(EncodedString)
    print "[*] Decoded"
    File.WriteAllBytes(Destination, rawdata)
    print "[*] Saved"
