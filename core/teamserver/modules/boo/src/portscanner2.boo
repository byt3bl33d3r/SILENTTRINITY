import System
import System.IO
import System.Net
import System.Net.Sockets
import System.Text
import System.Text.RegularExpressions
import System.Threading

public static def PortScan (portstart as string, portstop as string, ctrthread as string, host as string, timeOut as string):

		ctrThread = int.Parse(ctrthread);
		portStart = int.Parse(portstart);
		portStop = int.Parse(portstop);
		timeout = int.Parse(timeOut);
		
		ps = PortScanner(host, portStart, portStop, timeout)
		ps.start(ctrThread)

public class PortScanner:

	private host as string

	private portList as PortList

	private turnOff = true

	private count = 0

	public tcpTimeout as int

	private class isTcpPortOpen:

		public MainClient as TcpClient:
			get:
				pass
			set:
				pass

		public tcpOpen as bool:
			get:
				pass
			set:
				pass

	public def constructor(host as string, portStart as int, portStop as int, timeout as int):
		self.host = host
		portList = PortList(portStart, portStop)
		tcpTimeout = timeout

	public def start(threadCounter as int):
		for i in range(0, threadCounter):
			thread1 = Thread(ThreadStart(RunScanTcp))
			thread1.Start()

	public def RunScanTcp():
		tcp = TcpClient()
		port as int
		while (port = portList.NextPort()) != (-1):
			count = port
			Thread.Sleep(1)
			try:

				tcp = TcpClient(host, port)
			except :
				continue 
			Console.ForegroundColor = ConsoleColor.Green
			Console.WriteLine()
			Console.WriteLine('TCP Port {0} is open ', port)

			try:
				Console.ForegroundColor = ConsoleColor.Yellow
				Console.WriteLine(BannerGrab(host, port, tcpTimeout))
			except ex as Exception:
				Console.ForegroundColor = ConsoleColor.Red
				Console.WriteLine(('Could not retrieve the Banner ::Original Error = ' + ex.Message))
				Console.ResetColor()
			Console.ForegroundColor = ConsoleColor.Green
			webpageTitle as string = GetPageTitle(((('http://' + host) + ':') + port.ToString()))
			if not string.IsNullOrWhiteSpace(webpageTitle):
				Console.WriteLine((((((('Webpage Title = ' + webpageTitle) + 'Found @ :: ') + 'http://') + host) + ':') + port.ToString()))
			else:
				Console.ForegroundColor = ConsoleColor.DarkMagenta
				Console.WriteLine(((('Maybe A Login popup or a Service Login Found @ :: ' + host) + ':') + port.ToString()))
				Console.ResetColor()
			Console.ResetColor()

	public def BannerGrab(hostName as string, port as int, timeout as int) as string:
		newClient = TcpClient(hostName, port)
		newClient.SendTimeout = timeout
		newClient.ReceiveTimeout = timeout
		ns as NetworkStream = newClient.GetStream()
		sw = StreamWriter(ns)
		sw.Write(('HEAD / HTTP/1.1\r\n\r\n' + 'Connection: Closernrn'))
		sw.Flush()
		bytes as (byte) = array(byte, 2048)
		bytesRead as int = ns.Read(bytes, 0, bytes.Length)
		response as string = Encoding.ASCII.GetString(bytes, 0, bytesRead)
		return response

	private static def GetPageTitle(link as string) as string:
		try:
			x = WebClient()
			sourcedata as string = x.DownloadString(link)
			getValueTitle as string = Regex.Match(sourcedata, '\\<title\\b[^>]*\\>\\s*(?<Title>[\\s\\S]*?)\\</title\\>', RegexOptions.IgnoreCase).Groups['Title'].Value
			return getValueTitle
		except ex as Exception:
			#Console.ForegroundColor = ConsoleColor.Red
			#Console.WriteLine(('Could not connect. Error:' + ex.Message))
			#Console.ResetColor()
			return ''

public class PortList:

	private start as int

	private stop as int

	private ports as int

	public def constructor(starts as int, stops as int):
		start = starts
		stop = stops
		ports = start

	public def MorePorts() as bool:
		return ((stop - ports) >= 0)

	public def NextPort() as int:
		if MorePorts():
			return (ports++)
		return (-1)

public static def Main():
	portstart = "PORTSTART"
	portstop = "PORTEND"
	ctrthread = "CTRTHREAD"
	host = "HOST"
	timeOut = "TIMEOUT"
	PortScan(portstart,portstop,ctrthread,host,timeOut)
