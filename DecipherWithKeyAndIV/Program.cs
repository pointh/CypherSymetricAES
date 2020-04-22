using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace DecipherWithKeyAndIV
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length < 3)
            {
                Console.WriteLine("DecipherWithKeyAndIV message, key, iv");
                return;
            }

            byte[] decoded = Decrypt(
                ReadHexaString(args[0]),
                ReadHexaString(args[1]),
                ReadHexaString(args[2]));

            Console.WriteLine(Encoding.GetEncoding("UTF-16").GetString(decoded));

            Console.ReadLine();
        }

        static byte[] Decrypt(byte[] data, byte[] key, byte[] iv)
        {
            WriteByteArray(data);
            using (var aes = Aes.Create())
            {
                aes.Key = key; // sdílené tajné
                aes.IV = iv; // získané z předchozího šifrování
                aes.Mode = CipherMode.CBC; // musí být stejné jako pro Encrypt

                using (var cryptoTransform = aes.CreateDecryptor())
                {
                    return cryptoTransform.TransformFinalBlock(data, 0, data.Length);
                }
            }
        }

        static void WriteByteArray(byte[] arr)
        {
            foreach (byte b in arr)
                Console.Write(b.ToString("X2"));
            Console.WriteLine();
            string s = Convert.ToBase64String(arr);
            Console.WriteLine(s);
            byte[] oneMore = Convert.FromBase64String(s);
            foreach (byte b in oneMore)
                Console.Write(b.ToString("X2"));
        }

        static byte[] ReadHexaString(string s)
        {
            string hexChars = "0123456789ABCDEF";
            byte[] result = new byte[s.Length / 2];

            for (int i = 0; i < s.Length; i += 2)
            {
                string oneHex = s[i].ToString() + s[i + 1].ToString();
                result[i / 2] = (byte)(hexChars.IndexOf(oneHex[0]) * 16 + hexChars.IndexOf(oneHex[1]));
            }
            return result;
        }
    }
}
