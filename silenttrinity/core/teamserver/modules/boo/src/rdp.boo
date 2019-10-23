import System
import System.Diagnostics
import System.IO
import Microsoft.Win32
import System.Net
import System.Net.Sockets

// Enable RDP and Remote Assistance on remote machine via Registry

public static def enable():
		key as Microsoft.Win32.RegistryKey
		key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey('SYSTEM\\CurrentControlSet\\Control\\Terminal Server')
		key.SetValue('fDenyTSConnections', '0', RegistryValueKind.DWord)
		key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey('SYSTEM\\CurrentControlSet\\Control\\Terminal Server')
		key.SetValue('fAllowToGetHelp', '1')
		key.Close()

		using tcpClient = TcpClient():
			try:
				tcpClient.Connect('127.0.0.1', 3389)
				Console.WriteLine('3389/tcp open ms-wbt-server')
			except converterGeneratedName1 as Exception:
				Console.WriteLine('3389/tcp closed ms-wbt-server')
			Console.WriteLine('Remote Desktop has been enabled')
	
public static def disable():
		key as Microsoft.Win32.RegistryKey
		try:
			key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey('SYSTEM\\CurrentControlSet\\Control\\Terminal Server', true)
			if key is not null:
				try:
					key.DeleteValue('fDenyTSConnections')
					key.Close()
				except ex as Exception:
					Console.WriteLine(('[-] Unable to Delete the Registry key (Environment). Error ' + ex.Message))
			Console.WriteLine('[+] Registry Cleaned.')
		except :
			Console.WriteLine('[-] Unable to Clean the Registry.')

		key.Close()

		using tcpClient = TcpClient():
			try:
				System.Threading.Thread.Sleep(2);
				tcpClient.Connect('127.0.0.1', 3389)
				Console.WriteLine('3389/tcp open ms-wbt-server')
			except converterGeneratedName1 as Exception:
				Console.WriteLine('3389/tcp closed ms-wbt-server')
			Console.WriteLine('Remote Desktop has been disabled')
				

public static def Main():
	status()