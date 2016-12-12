using System;
using System.IO;

namespace JosePCL.Keys.pem
{
    public sealed class Pem
    {
        private string type;
        private string base64Encoded;

        private const string PemStart = "-----BEGIN ";
        private const string PemEnd = "-----END ";
        private const string PemEndOfLine = "-----";

        public Pem(string content)
        {
            using (var reader = new StringReader(content.Trim()))
            {
                string line;
                while ((line = reader.ReadLine()) != null)
                {
                    if (line.StartsWith(PemStart) && line.EndsWith(PemEndOfLine))
                    {
                        type = line.Substring(PemStart.Length, line.Length - PemStart.Length - PemEndOfLine.Length);
                    }

                    else if (line.StartsWith(PemEnd))
                    {
                        //ignore    
                    }

                    else
                    {
                        base64Encoded += line;
                    }
                }
            }
        }

        public string Type
        {
            get { return type; }
        }

        public byte[] Decoded
        {
            get { return Convert.FromBase64String(base64Encoded); }
        }
    }
}