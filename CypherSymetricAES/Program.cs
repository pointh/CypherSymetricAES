using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace CypherSymetricAES
{
    class Program
    {
        static void Main()
        {
            const string topSecret = "Kdo je vynálezcem kontaktních čoček?";
            RandomNumberGenerator rnd = RandomNumberGenerator.Create(); // Random kryptografické kvality!
            byte[] key = new byte[256 / 8]; // délka klíče je 32 bytů
            rnd.GetBytes(key); // utajovaný sdílený klíč, generuje se celé pole, ne jedno číslo

            Console.WriteLine($"Původní text: {topSecret}");
            
            Console.Write("Key: ");
            WriteByteArray(key);

            byte[] data = Encoding.GetEncoding("UTF-16").GetBytes(topSecret);
            // 16 bitový unicode https://cs.wikipedia.org/wiki/UTF-16
            // šifrujeme vždy byte[]!

            // {------------------------- Jedna šifrovací sekvence ------------------}
            byte[] iv;
            var encryptedData = Encrypt(data, key, out iv); 
            // klíč je tajný, IV ne. Encrypt ho náhodně generuje, proto out byte[]!
            Console.WriteLine($"Zašifrováno: {Encoding.GetEncoding("UTF-16").GetString(encryptedData)}");
            

            Console.Write("IV: ");
            WriteByteArray(iv);

            Console.Write("Encrypted data: ");
            WriteByteArray(encryptedData);

            var decryptedData = Decrypt(encryptedData, key, iv);
            // stejný inicializační vektor, stejný klíč!
            Console.WriteLine($"Dešifrováno: {Encoding.GetEncoding("UTF-16").GetString(decryptedData)}");
           
            
            // {------------------------- Jedna šifrovací sekvence ------------------}

            Console.ReadLine();
        }

        static byte[] Encrypt(byte[] data, byte[] key, out byte[] iv)
        {
            using (var aes = Aes.Create())
            {
                aes.Mode = CipherMode.CBC; 
                // mimo náš rozsah ... musíme si pamatovat, že aes.Mode musíme nastavit z enum CipherMode
                aes.Key = key;
                aes.GenerateIV(); // Pro každou šifrovací sekvenci je jiný. Pro dešifrování ho potřebujeme!

                using (var cryptoTransform = aes.CreateEncryptor())
                // generuje objekt pro šifrování, který obsahuje i nový iniciační vektor!
                // prozkoumat aes.
                {
                    iv = aes.IV; // Jen abychom ho mohli vrátit z metody pro další dešifrování
                    return cryptoTransform.TransformFinalBlock(data, 0, data.Length);
                }
            }
        }

        static byte[] Decrypt(byte[] data, byte[] key, byte[] iv)
        {
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
        }
    }
}
