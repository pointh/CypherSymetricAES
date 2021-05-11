using System;
using System.Security.Cryptography;

namespace CypherAsymetricRSA
{
    class Program
    {
        static void Main(string[] args)
        {
            byte[] data = new byte[8];
            
            RandomNumberGenerator.Create().GetBytes(data);
            WriteByteArray(data);

            // RSAParameters publicKey, privateKey;
            // nebo
            // xml string publicKey, privateKey

            string publicKey, privateKey;
            GenerateKeys(2048, out publicKey, out privateKey);

            var encryptedData = Encrypt(data, publicKey);
            var decryptedData = Decrypt(encryptedData, privateKey);
            WriteByteArray(decryptedData);
        }

        static void WriteByteArray(byte[] arr)
        {
            Console.WriteLine(string.Join(", ", arr));
        }

        static void GenerateKeys(int keyLength, out string publicKey, out string privateKey)
        // nebo 
        //static void GenerateKeys(int keyLength, out RSAParameters publicKey, out RSAParameters privateKey)
        {
            using (var rsa = RSA.Create())
            {
                rsa.KeySize = keyLength;
                //publicKey = rsa.ExportParameters(includePrivateParameters: false);
                //privateKey = rsa.ExportParameters(includePrivateParameters: true);
                privateKey = rsa.ToXmlString(true);
                publicKey = rsa.ToXmlString(false);
            }
        }

        static byte[] Encrypt(byte[] data, string publicKey)
        // static byte[] Encrypt(byte[] data, RSAParameters publicKey)
        {
            using (var rsa = RSA.Create())
            {
                //rsa.ImportParameters(publicKey);

                rsa.FromXmlString(publicKey);

                var result = rsa.Encrypt(data, RSAEncryptionPadding.Pkcs1);
                return result;
            }
        }

        static byte[] Decrypt(byte[] data, string privateKey)
        // static byte[] Decrypt(byte[] data, RSAParameters privateKey)
        {
            using (var rsa = RSA.Create())
            {
                // rsa.ImportParameters(privateKey);

                rsa.FromXmlString(privateKey);

                return rsa.Decrypt(data, RSAEncryptionPadding.Pkcs1);
            }
        }
    }
}
