using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Linq;

namespace Kaliya.Utils
{
    internal static class Resources
    {
        public static byte[] GetByName(string resourceName)
        {
            var query = $"Kaliya.Dependencies.{resourceName}";
            var asm = Assembly.GetExecutingAssembly();
            var res = asm.GetManifestResourceNames();
            var resQuery =
                from name in res
                where name == query
                select name;
            var resName = resQuery.Single();
            using (var resourceStream = asm.GetManifestResourceStream(resName))
            {
                using (var memoryStream = new MemoryStream())
                {
                    resourceStream?.CopyTo(memoryStream);
                    return memoryStream.ToArray();
                }
            }
        }
        
        public static byte[] GetResourceInZip(ZipStorer zip, string name)
        {
            foreach (var entry in zip.ReadCentralDir())
            {
                if (entry.FilenameInZip != name) continue;
                zip.ExtractFile(entry, out var data);
                return data;
            }

            return default;
        }
    }
}