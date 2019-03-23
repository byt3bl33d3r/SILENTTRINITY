using System;
using System.Security.Cryptography;
using System.Text;
using System.Linq;
using System.IO;
using System.Collections.Generic;

namespace SILENTTRINITY.Utilities
{
    public static class Crypto
    {
        // TODO: Migrate to self implemented Diffie-Hellman Key Exchange
        // ECDiffieHellmanCng is only available under Windows
        public static byte[] KeyExchange(Uri url)
        {
            byte[] key = default;

            using (ECDiffieHellmanCng AsymAlgo = new ECDiffieHellmanCng())
            {
                var publicKey = AsymAlgo.PublicKey.ToXmlString();
                byte[] response = Http.Post(url, Encoding.UTF8.GetBytes(publicKey));

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
                decryptedData = AES.Decrypt(ciphertext, key, iv);
            }
            return decryptedData;
        }

        public static byte[] Encrypt(byte[] key, byte[] data)
        {
            IEnumerable<byte> blob = default(byte[]);

            using (RandomNumberGenerator rng = new RNGCryptoServiceProvider())
            {
                byte[] iv = new byte[16];
                rng.GetBytes(iv);

                byte[] encryptedData = AES.Encrypt(data, key, iv);

                using (HMACSHA256 hmacsha256 = new HMACSHA256(key))
                {
                    byte[] ivEncData = iv.Concat(encryptedData).ToArray();
                    byte[] hmac = hmacsha256.ComputeHash(ivEncData);
                    blob = ivEncData.Concat(hmac);
                }
            }
            return blob.ToArray();
        }

        static class AES
        {
            public static byte[] Decrypt(byte[] data, byte[] key, byte[] iv)
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

            public static byte[] Encrypt(byte[] data, byte[] key, byte[] iv)
            {
                using (Aes aesAlg = Aes.Create())
                {
                    aesAlg.Padding = PaddingMode.PKCS7;
                    aesAlg.KeySize = 256;
                    aesAlg.Key = key;
                    aesAlg.IV = iv;

                    ICryptoTransform decryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                    using (MemoryStream encryptedData = new MemoryStream())
                    {
                        using (CryptoStream cryptoStream = new CryptoStream(encryptedData, decryptor, CryptoStreamMode.Write))
                        {
                            cryptoStream.Write(data, 0, data.Length);
                            cryptoStream.FlushFinalBlock();
                            return encryptedData.ToArray();
                        }
                    }
                }
            }
        }
    }
}
