using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace SILENTTRINITY.Utilities.Crypto
{
    public static class Base
    {
        public static byte[] KeyExchange(Uri url)
        {
            X9ECParameters x9EC = SecNamedCurves.GetByName("secp521r1");
            AsymmetricCipherKeyPair aliceKeyPair = GenerateKeyPair(
                                            new ECDomainParameters(x9EC.Curve,
                                        x9EC.G, x9EC.N, x9EC.H, x9EC.GetSeed()));

            ECPublicKeyParameters alicePublicKey = (ECPublicKeyParameters)aliceKeyPair.Public;
            ECPublicKeyParameters bobPublicKey = GetBobPublicKey(url, x9EC, alicePublicKey);

            return GenerateAESKey(bobPublicKey, aliceKeyPair.Private);
        }

        static byte[] GenerateAESKey(ECPublicKeyParameters bobPublicKey,
                                AsymmetricKeyParameter alicePrivateKey)
        {

            ECDHBasicAgreement aKeyAgree = new ECDHBasicAgreement();
            aKeyAgree.Init(alicePrivateKey);
            byte[] sharedSecret = aKeyAgree.CalculateAgreement(bobPublicKey).ToByteArray();

            // make sure each part has the correct and same size
            ResizeRight(ref sharedSecret, 66); // 66 is the desired key size

            Sha256Digest digest = new Sha256Digest();
            byte[] symmetricKey = new byte[digest.GetDigestSize()];
            digest.BlockUpdate(sharedSecret, 0, sharedSecret.Length);
            digest.DoFinal(symmetricKey, 0);

            return symmetricKey;
        }

        /// <summary>
        /// Resize but pad zeroes to the left instead of to the right like Array.Resize
        /// </summary>
        public static void ResizeRight(ref byte[] b, int length)
        {
            if (b.Length == length)
                return;
            if (b.Length > length)
                throw new NotSupportedException();

            byte[] newB = new byte[length];
            Array.Copy(b, 0, newB, length - b.Length, b.Length);
            b = newB;
        }

        static ECPublicKeyParameters GetBobPublicKey(Uri url,
                                                     X9ECParameters x9EC,
                                                     ECPublicKeyParameters alicePublicKey)
        {
            KeyCoords bobCoords = GetBobCoords(url, alicePublicKey);

            return new ECPublicKeyParameters("ECDH",
                        x9EC.Curve.ValidatePoint(bobCoords.X, bobCoords.Y).Normalize(),
                        SecObjectIdentifiers.SecP521r1);
        }

        static AsymmetricCipherKeyPair GenerateKeyPair(ECDomainParameters ecDomain)
        {
            ECKeyPairGenerator g = (ECKeyPairGenerator)GeneratorUtilities.GetKeyPairGenerator("ECDH");
            g.Init(new ECKeyGenerationParameters(ecDomain, new SecureRandom()));

            return g.GenerateKeyPair();
        }

        static KeyCoords GetBobCoords(Uri url, ECPublicKeyParameters publicKey)
        {
            string json = string.Format("{{'x': \"{0}\",'y': \"{1}\"}}",
                    publicKey.Q.Normalize().AffineXCoord,
                    publicKey.Q.Normalize().AffineYCoord
                );

            string response = Encoding.UTF8.GetString(Http.Post(url,
                                 Encoding.UTF8.GetBytes(json))).Replace("\"", "'");

            // Really ugly, but we're trying to reduce extra dependencies...
            MatchCollection mcx = new Regex(@"': (.+?) ").Matches(response);
            string mcy = response.Substring(response.LastIndexOf(": ",
                            StringComparison.Ordinal) + 1).Replace("}", "").Trim();

            return new KeyCoords
            {
                X = new BigInteger(mcx[0].Value.Replace("': ", "").Replace(", ", "")),
                Y = new BigInteger(mcy)
            };
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
                        throw new Exception("HMAC not valid");
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
    }

    class KeyCoords
    {
        public BigInteger X { get; set; }
        public BigInteger Y { get; set; }
    }
}
