//using System;
//using System.Threading.Tasks;
//using IdentityModel.OidcClient.Jwk;
//using System.Linq;

//namespace IdentityModel.OidcClient.IdentityTokenValidation
//{
//    public class JoseIdentityTokenValidator : IIdentityTokenValidator
//    {
//        public Task<IdentityTokenValidationResult> ValidateAsync(string identityToken, string clientId, ProviderInformation providerInformation)
//        {
//            var cert64 = GetKeyFromJwk(providerInformation.KeySet);
//            var pubkey = $"-----BEGIN PUBLIC KEY-----\n{cert64}\n-----END PUBLIC KEY-----";

//            var json = JosePCL.Jwt.Decode(identityToken, JosePCL.Keys.Rsa.PublicKey.Load(pubkey));


//            throw new NotImplementedException();
//        }

//        private string GetKeyFromJwk(JsonWebKeySet keySet)
//        {
//            return keySet.Keys.First().X5c.First();
//        }
//    }
//}