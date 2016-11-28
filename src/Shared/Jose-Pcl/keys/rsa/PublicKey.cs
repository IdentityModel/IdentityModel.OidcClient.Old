using System;
using JosePCL.Keys.pem;
using JosePCL.Util;
using PCLCrypto;

namespace JosePCL.Keys.Rsa
{
    public sealed class PublicKey
    {
        public static readonly byte[] BCRYPT_RSAPUBLIC_MAGIC = BitConverter.GetBytes(0x31415352);

        public static ICryptographicKey Load(string pubKeyContent)
        {
            CryptographicPublicKeyBlobType blobType;

            var block=new Pem(pubKeyContent);

            if (block.Type == null) //not pem encoded
            {
                //trying to guess blob type
                blobType = pubKeyContent.StartsWith("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A")
                    ? CryptographicPublicKeyBlobType.X509SubjectPublicKeyInfo
                    : CryptographicPublicKeyBlobType.Pkcs1RsaPublicKey;
            }
            else if ("PUBLIC KEY".Equals(block.Type))
            {
                blobType=CryptographicPublicKeyBlobType.X509SubjectPublicKeyInfo;   
            }
            else if ("RSA PUBLIC KEY".Equals(block.Type))
            {
                blobType = CryptographicPublicKeyBlobType.Pkcs1RsaPublicKey;
            }
            else
            {
                throw new Exception(string.Format("PublicKey.Load(): Unsupported type in PEM block '{0}'",block.Type));
            }

            return WinRTCrypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithm.RsaPkcs1)
                                                             .ImportPublicKey(block.Decoded, blobType);
        }

        public static ICryptographicKey New(byte[] exponent, byte[] modulus)
        {
            byte[] magic = BCRYPT_RSAPUBLIC_MAGIC;
            byte[] bitLength = BitConverter.GetBytes(modulus.Length * 8);
            byte[] expLength = BitConverter.GetBytes(exponent.Length);
            byte[] modLength = BitConverter.GetBytes(modulus.Length);
            byte[] prime1Length = BitConverter.GetBytes(0x00000000);
            byte[] prime2Length = BitConverter.GetBytes(0x00000000);

            byte[] blob = Arrays.Concat(magic, bitLength, expLength, modLength, prime1Length, prime2Length, exponent, modulus);

            return WinRTCrypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithm.RsaPkcs1)
                                                             .ImportPublicKey(blob, CryptographicPublicKeyBlobType.BCryptPublicKey);
        }

    }
}