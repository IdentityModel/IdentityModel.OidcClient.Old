using Newtonsoft.Json.Linq;

namespace IdentityModel.OidcClient.IdentityTokenValidation
{
    internal class ValidatedToken : Result
    {
        public string KeyId { get; set; }
        public string Algorithm { get; set; }
        public JObject Payload { get; set; }
    }
}