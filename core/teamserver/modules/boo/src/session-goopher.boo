import System
import System.Collections.Generic
import System.IO
import System.Linq
import System.Text.RegularExpressions

// Resursive call for each subdirectory.
//int rdpUsernameIDX = rdpFile.FindIndex(s => new Regex(@"username").Match(s).Success);
//int rdpIsAdminIDX = rdpFile.FindIndex(s => new Regex(@"administrative session").Match(s).Success);

//List<string> rdpUsername = rdpFile[rdpUsernameIDX].Split(':').ToList(); //This will error out if there is no specified username
//List<string> rdpIsAdmin = rdpFile[rdpIsAdminIDX].Split(':').ToList(); //This key isn't present in my test files

//Console.WriteLine("Username:\t\t" + rdpUsername[2]);
//Console.WriteLine("Session in Admin:\t" + rdpIsAdmin[1]);
[module]
public class SessionSearcher:

	private static def Main():
		Console.WriteLine('[+] Searching all connected drives. This could take a few minutes...')
		drives as (string) = Environment.GetLogicalDrives()
		for drive as string in drives:
			di = DriveInfo(drive)
			if not di.IsReady:
				Console.WriteLine('Drive {0} could not be read', di.Name)
				continue 
			rootDir as DirectoryInfo = di.RootDirectory
			RecursiveFileSearch(rootDir)
		Console.WriteLine('[+] Parsing PPK files\r\n')
		for ppkFile as string in ppkList:
			PPKParser(ppkFile)
		Console.WriteLine('[+] Parsing RDP files\r\n')
		for rdpFile as string in rdpList:
			RDPParser(rdpFile)
		Console.WriteLine('[+] Collected RSA tokens:\r\n')
		for sdtidFile as string in sdtidList:
			Console.WriteLine(sdtidFile)

	private static ppkList as List[of string] = List[of string]()

	private static rdpList as List[of string] = List[of string]()

	private static sdtidList as List[of string] = List[of string]()

	private static def RecursiveFileSearch(root as DirectoryInfo):
		files as (FileInfo) = null
		subDirs as (DirectoryInfo) = null
		try:
			files = root.GetFiles('*.*')
		except converterGeneratedName1 as UnauthorizedAccessException:
			pass
		except converterGeneratedName2 as DirectoryNotFoundException:
			pass
		if files is not null:
			for fi as FileInfo in files:
				if fi.Extension.Equals('.ppk'):
					ppkList.Add(fi.FullName)
					Console.WriteLine(fi.FullName)
				if fi.Extension.Equals('.rdp'):
					rdpList.Add(fi.FullName)
					Console.WriteLine(fi.FullName)
				if fi.Extension.Equals('.sdtid'):
					sdtidList.Add(fi.FullName)
					Console.WriteLine(fi.FullName)
			subDirs = root.GetDirectories()
			for dirInfo as DirectoryInfo in subDirs:
				RecursiveFileSearch(dirInfo)

	private static def PPKParser(path as string):
		lines as List[of string] = File.ReadAllLines(path).ToList()
		protocol as List[of string] = lines[0].Split(char(':')).ToList()
		encryption as List[of string] = lines[1].Split(char(':')).ToList()
		comment as List[of string] = lines[2].Split(char(':')).ToList()
		mac as List[of string] = lines[(lines.Count - 1)].Split(char(':')).ToList()
		privateKeyLenIndex as int = lines.FindIndex({ s | return Regex('Private-Lines').Match(s).Success })
		indexofPrivateKeyLen as List[of string] = lines[privateKeyLenIndex].Split(char(':')).ToList()
		privateKeylen as int = Convert.ToInt32(indexofPrivateKeyLen[1].Replace(' ', String.Empty))
		endofPrivateKey as int = (privateKeylen + privateKeyLenIndex)
		privateKey as string = null
		for i in range((privateKeyLenIndex + 1), (endofPrivateKey + 1)):
			privateKey += lines[i]
		Console.WriteLine(('Filename:\t ' + path))
		Console.WriteLine(('Protocol:\t' + protocol[1]))
		Console.WriteLine(('Comment:\t' + comment[1]))
		Console.WriteLine(('Encryption:\t' + encryption[1]))
		Console.WriteLine(('Private Key:\t ' + privateKey))
		Console.WriteLine(('Private Mac:\t' + mac[1]))
		Console.WriteLine()

	private static def RDPParser(path as string):
		rdpFile as List[of string] = File.ReadAllLines(path).ToList()
		rdpAddressIDX as int = rdpFile.FindIndex({ s | return Regex('full address').Match(s).Success })
		rdpGatewayIDX as int = rdpFile.FindIndex({ s | return Regex('gatewayhostname').Match(s).Success })
		rdpPromptForCredsIDX as int = rdpFile.FindIndex({ s | return Regex('prompt for credentials').Match(s).Success })
		rdpAddress as List[of string] = rdpFile[rdpAddressIDX].Split(char(':')).ToList()
		rdpGateway as List[of string] = rdpFile[rdpGatewayIDX].Split(char(':')).ToList()
		rdpPromptForCredsArr as List[of string] = rdpFile[rdpPromptForCredsIDX].Split(char(':')).ToList()
		Console.WriteLine(('Filename:\t\t' + path))
		Console.WriteLine(('Address:\t\t' + rdpAddress[2]))
		Console.WriteLine(('Gateway Address:\t' + rdpGateway[2]))
		if rdpPromptForCredsArr[2].ToString().Equals('0'):
			Console.WriteLine('Prompts for Creds:\tFalse')
		else:
			Console.WriteLine('Prompts for Creds:\tTrue')
		Console.WriteLine()