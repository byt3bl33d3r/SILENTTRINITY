using System;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Linq;
using System.IO;

namespace SILENTTRINITY.Utilities
{
    public static class Crypto
    {
        // TODO: Migrate to self implemented Diffie-Hellman Key Exchange
        async public static Task<byte[]> KeyExchangeAsync(Uri URL, string Endpoint = "")
        {
            byte[] key = default(byte[]);

            using (ECDiffieHellmanCng AsymAlgo = new ECDiffieHellmanCng())
            {
                var publicKey = AsymAlgo.PublicKey.ToXmlString();
                byte[] response = await Http.PostAsync(URL, Encoding.UTF8.GetBytes(publicKey));

                ECDiffieHellmanCngPublicKey peerPublicKey = 
                    ECDiffieHellmanCngPublicKey.FromXmlString(Encoding.UTF8.GetString(response));
                key = AsymAlgo.DeriveKeyMaterial(peerPublicKey);
            }

            return key;
        }

        public static byte[] Decrypt(byte[] key, byte[] data)
        {
            byte[] decryptedData = default(byte[]);

            byte[] iv = new byte[16];
            byte[] ciphertext = new byte[(data.Length - 32) - 16];
            byte[] hmac = new byte[32];

            Array.Copy(data, iv, 16);
            Array.Copy(data, data.Length - 32, hmac, 0, 32);
            Array.Copy(data, 16, ciphertext, 0, (data.Length - 32) - 16);

            using (HMACSHA256 hmacsha256 = new HMACSHA256(key))
            {
                byte[] computedHash = hmacsha256.ComputeHash(iv.Concat(ciphertext).ToArray());
                for (int i = 0; i < hmac.Length; i++)
                {
                    if (computedHash[i] != hmac[i])
                    {
                        return decryptedData;
                    }
                }
                decryptedData = AesDecrypt(ciphertext, key, iv);
            }
            return decryptedData;
        }

        private static byte[] AesDecrypt(byte[] data, byte[] key, byte[] iv)
        {
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Padding = PaddingMode.PKCS7;
                aesAlg.KeySize = 256;
                aesAlg.Key = key;
                aesAlg.IV = iv;

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream decryptedData = new MemoryStream())
                {
                    using (CryptoStream cryptoStream = new CryptoStream(decryptedData, decryptor, CryptoStreamMode.Write))
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
