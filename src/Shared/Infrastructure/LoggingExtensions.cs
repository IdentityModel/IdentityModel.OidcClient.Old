using IdentityModel.OidcClient.Logging;
using System.Diagnostics;

namespace IdentityModel.OidcClient
{
    internal static class LoggingExtensions
    {
        [DebuggerStepThrough]
        public static void LogClaims(this ILog logger, Claims claims)
        {
            foreach (var claim in claims)
            {
                logger.Debug($"Claim: {claim.Type}: {claim.Value}");
            }
        }
    }
}