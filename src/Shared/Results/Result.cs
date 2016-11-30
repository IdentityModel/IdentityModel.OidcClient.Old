namespace IdentityModel.OidcClient
{
    public class Result
    {
        public bool Success => !string.IsNullOrWhiteSpace(Error);
        public string Error { get; set; }
    }
}