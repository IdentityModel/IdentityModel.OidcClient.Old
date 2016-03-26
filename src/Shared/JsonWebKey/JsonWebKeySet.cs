using System;
using System.Collections.Generic;
using Newtonsoft.Json;

namespace IdentityModel.OidcClient.Jwk
{
    /// <summary>
    /// Contains a collection of <see cref="JsonWebKey"/> that can be populated from a json string.
    /// </summary>
    /// <remarks>provides support for http://tools.ietf.org/html/rfc7517.</remarks>
    public class JsonWebKeySet
    {
        private List<JsonWebKey> _keys = new List<JsonWebKey>();

        /// <summary>
        /// Initializes an new instance of <see cref="JsonWebKeySet"/>.
        /// </summary>
        public JsonWebKeySet()
        {
        }

        /// <summary>
        /// Initializes an new instance of <see cref="JsonWebKeySet"/> from a json string.
        /// </summary>
        /// <param name="json">a json string containing values.</param>
        /// <exception cref="ArgumentNullException">if 'json' is null or whitespace.</exception>
        public JsonWebKeySet(string json)
        {
            //if (string.IsNullOrWhiteSpace(json))
            //    throw LogHelper.LogArgumentNullException("json");

            try
            {
                //IdentityModelEventSource.Logger.WriteVerbose(LogMessages.IDX10806);
                var jwebKeys = JsonConvert.DeserializeObject<JsonWebKeySet>(json);
                _keys = jwebKeys._keys;
            }
            catch (Exception ex)
            {
                //throw LogHelper.LogException<ArgumentException>(ex, LogMessages.IDX10804, json);
            }
        }

        /// <summary>
        /// Gets the <see cref="IList{JsonWebKey}"/>.
        /// </summary>       
        public IList<JsonWebKey> Keys
        {
            get
            {
                return _keys;
            }
        }

        ///// <summary>
        ///// Returns the JsonWebKeys as a <see cref="IList{SecurityKey}"/>.
        ///// </summary>
        //public IList<SecurityKey> GetSigningKeys()
        //{
        //    List<SecurityKey> keys = new List<SecurityKey>();
        //    for (int i = 0; i < _keys.Count; i++)
        //    {
        //        JsonWebKey webKey = _keys[i];

        //        if (!StringComparer.Ordinal.Equals(webKey.Kty, JsonWebAlgorithmsKeyTypes.RSA))
        //            continue;

        //        if ((string.IsNullOrWhiteSpace(webKey.Use) || (StringComparer.Ordinal.Equals(webKey.Use, JsonWebKeyUseNames.Sig))))
        //        {
        //            if (webKey.X5c != null)
        //            {
        //                foreach (var certString in webKey.X5c)
        //                {
        //                    try
        //                    {
        //                        // Add chaining
        //                        SecurityKey key = new X509SecurityKey(new X509Certificate2(Convert.FromBase64String(certString)));
        //                        key.KeyId = webKey.Kid;
        //                        keys.Add(key);
        //                    }
        //                    catch (CryptographicException ex)
        //                    {
        //                        throw LogHelper.LogException<InvalidOperationException>(ex, LogMessages.IDX10802, webKey.X5c[0]);
        //                    }
        //                    catch (FormatException fex)
        //                    {
        //                        throw LogHelper.LogException<InvalidOperationException>(fex, LogMessages.IDX10802, webKey.X5c[0]);
        //                    }
        //                }
        //            }

        //            if (!string.IsNullOrWhiteSpace(webKey.E) && !string.IsNullOrWhiteSpace(webKey.N))
        //            {
        //                try
        //                {
        //                    SecurityKey key =
        //                         new RsaSecurityKey
        //                         (
        //                            new RSAParameters
        //                            {
        //                                Exponent = Base64UrlEncoder.DecodeBytes(webKey.E),
        //                                Modulus = Base64UrlEncoder.DecodeBytes(webKey.N),
        //                            }

        //                        );
        //                    key.KeyId = webKey.Kid;
        //                    keys.Add(key);
        //                }
        //                catch (CryptographicException ex)
        //                {
        //                    throw LogHelper.LogException<InvalidOperationException>(ex, LogMessages.IDX10801, webKey.E, webKey.N);
        //                }
        //                catch (FormatException ex)
        //                {
        //                    throw LogHelper.LogException<InvalidOperationException>(ex, LogMessages.IDX10801, webKey.E, webKey.N);
        //                }
        //            }
        //        }
        //    }

        //    return keys;
        //}
    }
}