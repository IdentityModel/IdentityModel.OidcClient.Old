using System.Runtime.InteropServices.WindowsRuntime;
using System.Text;

namespace JosePCL.Serialization
{
    public sealed class Compact
    {
        public static Part[] Parse(string token)
        {
            string[] parts = token.Split('.');

            var result = new Part[parts.Length];

            for (var i = 0; i < parts.Length; i++)
            {
                result[i]=new Part(Base64Url.Decode(parts[i]));
            }

            return result;
        }

        public static string Serialize(params Part[] parts)
        {
            var builder = new StringBuilder();

            foreach (var part in parts)
            {
                builder.Append(Base64Url.Encode(part.Bytes)).Append(".");
            }

            builder.Remove(builder.Length - 1, 1);

            return builder.ToString();
        }
    }

    public sealed class Part
    {
        private byte[] _bytes;

        public static Part New(string data)
        {
            return new Part(Encoding.UTF8.GetBytes(data));
        }

        public Part([ReadOnlyArray] byte[] bytes)
        {
            _bytes = bytes;
        }       

        public byte[] Bytes
        {
            get { return _bytes; }
        }

        public string Utf8
        {
            get { return Encoding.UTF8.GetString(_bytes, 0, _bytes.Length); }
        }
    }
}