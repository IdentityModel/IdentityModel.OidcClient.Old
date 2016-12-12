using System.Runtime.InteropServices.WindowsRuntime;
using JosePCL.Util;
using PCLCrypto;

namespace JosePCL.Jws
{
    public sealed class HmacUsingSha : IJwsSigner
    {
        private int keySizeBits;

        public HmacUsingSha(int keySizeBits)
        {
            this.keySizeBits = keySizeBits;
        }

        public byte[] Sign([ReadOnlyArray] byte[] securedInput, object key)
        {
            var sharedKey = Ensure.Type<byte[]>(key, "HmacUsingSha expects key to be byte[] array.");

            var hmacKey = AlgProvider.CreateKey(sharedKey);

            return WinRTCrypto.CryptographicEngine.Sign(hmacKey, securedInput);
        }

        public bool Verify([ReadOnlyArray] byte[] signature, [ReadOnlyArray] byte[] securedInput, object key)
        {
            var sharedKey = Ensure.Type<byte[]>(key, "HmacUsingSha expects key to be byte[] array.");

            var hmacKey=AlgProvider.CreateKey(sharedKey);

            return WinRTCrypto.CryptographicEngine.VerifySignature(hmacKey, securedInput, signature);
        }

        public string Name
        {
            get
            {
                switch (keySizeBits)
                {
                    case 256: return JwsAlgorithms.HS256;
                    case 384: return JwsAlgorithms.HS384;
                    default: return JwsAlgorithms.HS512;
                }
            }            
        }

        private IMacAlgorithmProvider AlgProvider
        {
            get
            {
                switch (keySizeBits)
                {
                    case 256: return WinRTCrypto.MacAlgorithmProvider.OpenAlgorithm(MacAlgorithm.HmacSha256);
                    case 384: return WinRTCrypto.MacAlgorithmProvider.OpenAlgorithm(MacAlgorithm.HmacSha384);
                    default: return WinRTCrypto.MacAlgorithmProvider.OpenAlgorithm(MacAlgorithm.HmacSha512); 
                } 
            }
        }
    }
}