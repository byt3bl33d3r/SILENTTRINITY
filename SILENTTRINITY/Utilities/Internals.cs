using System.IO.Compression;

namespace SILENTTRINITY.Utilities
{
    public static class Internals
    {
        public static string GetDLLName(string name)
        {
            string DllName = name + ".dll";

            if (name.IndexOf(',') > 0)
            {
                DllName = name.Substring(0, name.IndexOf(',')) + ".dll";
            }

            return DllName;
        }

        public static byte[] GetResourceInZip(ZipStorer zip, string resourceName)
        {
            foreach (var entry in zip.ReadCentralDir())
            {
                if (entry.FilenameInZip == resourceName)
                {
                    var resdata = new byte[entry.FileSize];
                    zip.ExtractFile(entry, out resdata);
                    return resdata;
                }
            }
            return default;
        }

    }
}
