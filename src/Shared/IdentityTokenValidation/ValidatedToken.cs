using Newtonsoft.Json.Linq;

namespace IdentityModel.OidcClient.IdentityTokenValidation
{
    internal class ValidatedToken
    {
        public bool Success { get; set; }
        public string Error { get; set; }

        public string KeyId { get; set; }
        public string Algorithm { get; set; }
        public JObject Payload { get; set; }
    }
}