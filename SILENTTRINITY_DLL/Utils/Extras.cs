using System;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Resources;

namespace Kaliya.Utils
{
    public static class Extras
    {
        public static string GetDllName(string name)
        {
            var dllName = name + ".dll";
            if (name.IndexOf(',') > 0)
            {
                dllName = name.Substring(0, name.IndexOf(',')) + ".dll";
            }

            return dllName;
        }

        public static byte[] GetResourceFromZip(ZipStorer zip, string name)
        {
            foreach (var entry in zip.ReadCentralDir())
            {
                if (entry.FilenameInZip != name) continue;
                zip.ExtractFile(entry, out var data);
                return data;
            }

            return default;
        }

        internal static byte[] GetResourceByName(string resName)
        {
            var asm = System.Reflection.Assembly.GetExecutingAssembly();
            var resource = asm.GetManifestResourceNames().Where(x => x.EndsWith(resName)).FirstOrDefault();
            using (var resourceStream = asm.GetManifestResourceStream(resource))
            {
                using (var memoryStream = new MemoryStream())
                {
                    resourceStream?.CopyTo(memoryStream);
                    return memoryStream.ToArray();
                }
            }
        }
    }
}