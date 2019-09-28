import System
import System.Text
import System.Net
import System.Net.Sockets
import System.Threading

public static def PortScan (portstart as string, portstop as string, ctrthread as string, host as string):	
		
		ctrThread = int.Parse(ctrthread);
		portStart = int.Parse(portstart);
		portStop = int.Parse(portstop);

		ps = PortScanner(host, portStart, portStop)
		ps.start(ctrThread)

	private static def printUsage():
		Console.WriteLine('Usage: PortScanner target-name [starting-port ending-port] [no-threads]\n')
		Console.WriteLine('Where\n\tstarting-port\tStarting port number. Default is 1')
		Console.WriteLine('\tending-port\tEnding port number. Default is 65535.')
		Console.WriteLine('\tno-threads\tNumber of threads. Default is 200')
		Console.WriteLine('\ttarget-name\tTarget host.\n')
		Console.WriteLine('Example 1: "PortScanner 127.0.0.1 1 10000" will scan for open TCP ports from port 0 to port 10000.\n')
		Console.WriteLine('Example 2: "PortScanner 127.0.0.1" will scan for open TCP ports from port 1 to port 65535.\n')

public class PortScanner:

	private host as string

	private portList as PortList

	public def constructor(host as string, portStart as int, portStop as int):
		self.host = host
		self.portList = PortList(portStart, portStop)

	public def constructor(host as string):
		self(host, 1, 65535)

	public def constructor():
		self('127.0.0.1')

	public def start(threadCtr as int):
		for i in range(0, threadCtr):
			th = Thread(ThreadStart(run))
			th.Start()

	public def run():
		port as int
		tcp = TcpClient()
		while (port = portList.getNext()) != (-1):
			try:
				tcp = TcpClient(host, port)
			except :
				continue 
			ensure:
				try:
					tcp.Close()
				except :
					pass
			Console.WriteLine((('TCP Port ' + port) + ' is open'))

public class PortList:

	private start as int

	private stop as int

	private ptr as int

	public def constructor(start as int, stop as int):
		self.start = start
		self.stop = stop
		self.ptr = start

	public def constructor():
		self(1, 65535)

	public def hasMore() as bool:
		return ((stop - ptr) >= 0)

	public def getNext() as int:
		if hasMore():
			return (ptr++)
		return (-1)
	

public static def Main():
	portstart = "PORTSTART"
	portstop = "PORTEND"
	ctrthread = "CTRTHREAD"
	host = "HOST"
	PortScan(portstart, portstop, ctrthread, host)




