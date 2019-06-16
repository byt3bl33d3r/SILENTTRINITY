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

Reading the source for the [IronPython Compiler](https://github.com/IronLanguages/ironpython2/tree/master/Src/IronPythonCompiler) it seems like we can get around the first issue by directly generating IL code through IKVM (I still don't understand why this works). However, this would require modifying the compiler to generate a completely new EXE stub (definitely feasible, just time consuming to find the proper IKVM API calls).

### Deployment with Docker
The server can be built as a docker container, reducing surface area of your machine to
potentially untrusted code.

From the root of the repository build the docker image with
```bash
docker build -t silenttrinity .
```
Run it with
```bash
docker run -it --rm --name trinity -p 8000:8000 -v $PWD/artifacts:/artifacts silenttrinity
```

Things to note:

 - The given command will mount the directory `./artifacts` in the container at `/artifacts` meaning that to get the stagers
 out of the container you will have to specify a filename eg. `generate http --filename=/artifacts/stager.ps1`
 - The `-p xxxx:yyyy` flag means, forward host port xxxx to container port yyyy. These values can be any valid TCP port
  you wish however, you will have to use yyyy as the Port for the listener, and when generating a stager you must set
  lhost to your host's IP (Not the container), and lport to xxxx
 - The `-p` flag can be repeated to forward multiple ports

### C2 Comms

Currently the implant only supports C2 over HTTP 1.1, .NET 4.5 seems to have a native WebSocket library which makes implementing a WS C2 channel more than possible.

HTTP/2 client support for .NET's `HttpClient` API is in the works, just not yet released.

The implant and server design are very much "future proof" which should make implementing these C2 Channels pretty trivial when the time comes.

### COM Interop

http://ironpython.net/documentation/dotnet/dotnet.html#oleautomation-and-com-interop

We could possibly leaverage this to use IE's COM object to do C2 ala [WSC2](https://github.com/Arno0x/WSC2).

~~Also shellcode injection via dynamic Office Macros.~~ (Done!)

### Python Standard Library

We technically could load/use IronPython's stdlib instead of calling .NET APIs but, this would require writing some "magic" dependency resolving code. 

Possibly could modify [httpimports](https://github.com/operatorequals/httpimport) to do this automagically.

### Inject into unmanaged process

https://www.codeproject.com/Articles/607352/Injecting-Net-Assemblies-Into-Unmanaged-Processes

We actually might not need to do any of that cause of some fantastic research from @xpn!

https://blog.xpnsec.com/rundll32-your-dotnet/

### RPC

We might want to implement a fully fledged RPC that proxies objects between C# and Python. This could be interesting:

- https://pythonhosted.org/Pyro4/pyrolite.html

- https://thrift.apache.org/

### Development Environment

You can refer to the [Wiki](https://github.com/byt3bl33d3r/SILENTTRINITY/wiki/Setting-up-your-development-environment) if you need some help setting up your environment.

### Reporting issues

Reporting any issue will be appreciated, but please, feel free to use this [ISSUE_TEMPLATE](https://github.com/byt3bl33d3r/SILENTTRINITY/blob/master/.github/ISSUE_TEMPLATE.md).
