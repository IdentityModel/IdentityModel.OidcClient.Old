using System;
using System.Collections.Generic;
using System.Text;
using JosePCL.Jws;
using JosePCL.Serialization;
using JosePCL.Util;
using Newtonsoft.Json;

namespace JosePCL
{
    public sealed class Jwt
    {
        private static IDictionary<string, IJwsSigner> signers = new Dictionary<string, IJwsSigner>();

        static Jwt()
        {
            RegisterJws(new Plaintext());
            RegisterJws(new HmacUsingSha(256));
            RegisterJws(new HmacUsingSha(384));
            RegisterJws(new HmacUsingSha(512));
            RegisterJws(new RsaUsingSha(256));
            RegisterJws(new RsaUsingSha(384));
            RegisterJws(new RsaUsingSha(512));          
        }

        public static void RegisterJws(IJwsSigner signer)
        {
            signers[signer.Name] = signer;
        }
      
        public static string Decode(string token, object key)
        {
            Ensure.IsNotEmpty(token, "JosePCL.Jwt.Decode(): token expected to be in compact serialization form, not empty, whitespace or null.");

            Part[] parts = Compact.Parse(token);

            if (parts.Length == 3) //just signed JWT
            {
                return Verify(parts, key);
            }

            throw new Exception(string.Format("JosePCL.Jwt.Decode(): expected token with 3 or 5 parts, but got:{0}.", parts.Length));
        }

        private static string Verify(Part[] parts, object key)
        {
            Part header = parts[0];
            Part payload = parts[1];
            Part signature = parts[2];

            byte[] securedInput = Encoding.UTF8.GetBytes(Compact.Serialize(header, payload));

            var headerData = JsonConvert.DeserializeObject<Dictionary<string, object>>(header.Utf8);

            var alg = headerData["alg"].ToString();

            if (!signers.ContainsKey(alg))
                throw new Exception(string.Format("JosePCL.Jwt.Verify(): unknown or unsupported algorithm:{0}.", alg));

            if (!signers[alg].Verify(signature.Bytes, securedInput, key))
                throw new Exception("JosePCL.Jwt.Verify(): Invalid signature."); 

            return payload.Utf8;
        }

        public static string Encode(string payload, string signingAlgorithm, object key)
        {
            Ensure.IsNotEmpty(payload, "JosePCL.Jwt.Encode(): payload expected to be not empty, whitespace or null.");

            if (!signers.ContainsKey(signingAlgorithm))
                throw new Exception(string.Format("JosePCL.Jwt.Encode(): unknown or unsupported signing algorithm:{0}.", signingAlgorithm));

            IJwsSigner signer = signers[signingAlgorithm];

            var jwtHeader = new Dictionary<string, string>
            {
                {"typ","JWT" },
                {"alg", signingAlgorithm}
            };

            var header = Part.New(JsonConvert.SerializeObject(jwtHeader));
            var content = Part.New(payload);
            var securedInput = Encoding.UTF8.GetBytes(Compact.Serialize(header, content));
            var signature = new Part(signer.Sign(securedInput, key)); 

            return Compact.Serialize(header, content, signature);
        }

        public static string Encode(string payload, string signingAlgorithm)
        {
            return Encode(payload, signingAlgorithm, null);
        }

    }
}

