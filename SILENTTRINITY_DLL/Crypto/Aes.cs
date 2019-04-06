using System;
using System.IO;
using System.Security.Cryptography;
using System.Linq;

namespace Kaliya.Crypto
{
    internal static class Aes
    {
        public static byte[] Decrypt(byte[] key, byte[] data)
        {
            byte[] decryptedData = default;

            var iv = new byte[16];
            var text = new byte[data.Length - 32 - 16];
            var hmac = new byte[32];

            Array.Copy(data, iv, 16);
            Array.Copy(data, data.Length - 32, hmac, 0, 32);
            Array.Copy(data, 16, text, 0, data.Length - 32 - 16);

            using (var hmacsha256 = new HMACSHA256(key))
            {
                var computedHash = hmacsha256.ComputeHash(iv.Concat(text).ToArray());
                if (hmac.Where((t, i) => computedHash[i] != t).Any())
                {
                    throw new Exception("HMAC not valid");
                }

                decryptedData = Decrypt(text, key, iv);
            }

            return decryptedData;
        }

        private static byte[] Decrypt(byte[] data, byte[] key, byte[] iv)
        {
            using (var aesAlg = System.Security.Cryptography.Aes.Create())
            {
                if (aesAlg == null) return default;
                aesAlg.Padding = PaddingMode.PKCS7;
                aesAlg.KeySize = 256;
                aesAlg.Key = key;
                aesAlg.IV = iv;

                var decrypt = aesAlg.CreateDecryptor(aesAlg.Key,
                    aesAlg.IV);

                using (var decryptedData = new MemoryStream())
                {
                    using (var cryptoStream =
                        new CryptoStream(decryptedData, decrypt,
                            CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(data, 0, data.Length);
                        cryptoStream.FlushFinalBlock();
                        return decryptedData.ToArray();
                    }
                }
            }
        }
    }
}