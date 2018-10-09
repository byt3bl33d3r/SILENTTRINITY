# SILENTTRINITY

<p align="center">
  <img src="https://user-images.githubusercontent.com/5151193/45964397-e462e280-bfe2-11e8-88a7-69212e0f0355.png" width=400 height=400 alt="ST"/>
</p>

## Requirements

- Server requires Python >= 3.7
- SILENTTRINITY C# implant requires .NET >= 4.5

## How it works
<p align="center">
  <img src="https://user-images.githubusercontent.com/5151193/46646842-cd2b0580-cb49-11e8-9218-73226e977d58.png" alt="ST"/>
</p>

## Notes

### .NET runtime support

The implant needs .NET 4.5 or greater due to the IronPython DLLs being compiled against .NET 4.0, also there is no `ZipArchive` .NET library prior to 4.5 which the implant relies upon to download the initial stage containing the IronPython DLLs and the main Python code.

Reading the source for the [IronPython Compiler](https://github.com/IronLanguages/ironpython2/tree/master/Src/IronPythonCompiler) it seems like we can get around the first issue by directly generating IL code through IKVM (I still don't understand why this works). However this would require modifying the compiler to generate a completely new EXE stub (definitely feasible, just time consuming to find the proper IKVM API calls).

### C2 Comms

Currently the implant only supports C2 over HTTP 1.1, .NET 4.5 seems to have a native WebSocket library which makes implementing a WS C2 channel more than possible.

HTTP/2 client support for .NET's `HttpClient` API is in the works, just not yet released.

The implant and server design are very much "future proof" which should make implementing these C2 Channels pretty trivial when the time comes.

### COM Interop

http://ironpython.net/documentation/dotnet/dotnet.html#oleautomation-and-com-interop

We could possibly leaverage this to use IE's COM object to do C2 ala [WSC2](https://github.com/Arno0x/WSC2)

~~Also shellcode injection via dynamic Office Macros.~~ (Done!)

### Python Standard Library

We technically could load/use IronPython's stdlib instead of calling .NET APIs but this would require writing some "magic" dependency resolving code. 

Possibly could modify [httpimports](https://github.com/operatorequals/httpimport) to do this automagically.

### Inject into unmanaged process

https://www.codeproject.com/Articles/607352/Injecting-Net-Assemblies-Into-Unmanaged-Processes

### RPC

We might want to implement a fully fledged RPC that proxies objects between C# and Python. This could be interesting...

- https://pythonhosted.org/Pyro4/pyrolite.html

- https://thrift.apache.org/
