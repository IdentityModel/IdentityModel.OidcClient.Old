using System;

namespace JosePCL.Util
{
    internal class Ensure
    {
        public static void IsNull(object key, string msg, params object[] args)
        {
            if (key != null)
                throw new ArgumentException(msg);
        }

        public static void Divisible(int arg, int divisor, string msg, params object[] args)
        {
            if (arg % divisor != 0)
                throw new ArgumentException(string.Format(msg, args));
        }

        public static void BitSize(byte[] array, uint expectedSize, string msg, params object[] args)
        {
            if (expectedSize != array.Length * 8)
                throw new ArgumentException(string.Format(msg, args));
        }

        public static void IsEmpty(byte[] arr, string msg, params object[] args)
        {
            if (arr.Length != 0)
                throw new ArgumentException(msg);
        }

        public static T Type<T>(object obj, string msg, params object[] args)
        {
            if (!(obj is T))
                throw new ArgumentException(string.Format(msg, args));

            return (T) obj;
        }

        public static void IsNotEmpty(string arg, string msg, params object[] args)
        {
            if (string.IsNullOrWhiteSpace(arg))
                throw new ArgumentException(string.Format(msg, args));
        }

        public static void SameSize(byte[] left, byte[] right, string msg, params object[] args)
        {
            if (left.Length != right.Length)
                throw new ArgumentException(string.Format(msg, args));
        }

        public static void MaxValue(int arg, long max, string msg, params object[] args)
        {
            if (arg > max)
                throw new ArgumentException(string.Format(msg, args));
        }

        public static void MinValue(int arg, int min, string msg, params object[] args)
        {
            if (arg < min)
                throw new ArgumentException(string.Format(msg, args));
        }

//        public static void Contains(JsonObject header, string name, string msg, params  object[] args)
//        {
//            if(!header.ContainsKey(name))
//                throw new ArgumentException(string.Format(msg, args));
//        }
    }
}