using System.Security.Cryptography;

namespace CypherAsymetricRSA
{
    class Program
    {
        static void Main(string[] args)
        {
            var data = new byte[] { 1, 2, 3 };
            RSAParameters publicKey, privateKey;

            GenerateKeys(2048, out publicKey, out privateKey);

            var encryptedData = Encrypt(data, publicKey);
            var decryptedData = Decrypt(encryptedData, privateKey);

        }

        static void GenerateKeys(int keyLength, out RSAParameters publicKey, out RSAParameters privateKey)
        {
            using (var rsa = RSA.Create())
            {
                rsa.KeySize = keyLength;
                publicKey = rsa.ExportParameters(includePrivateParameters: false);
                privateKey = rsa.ExportParameters(includePrivateParameters: true);
            }
        }

        static byte[] Encrypt(byte[] data, RSAParameters publicKey)
        {
            using (var rsa = RSA.Create())
            {
                rsa.ImportParameters(publicKey);

                var result = rsa.Encrypt(data, RSAEncryptionPadding.Pkcs1);
                return result;
            }
        }

        static byte[] Decrypt(byte[] data, RSAParameters privateKey)
        {
            using (var rsa = RSA.Create())
            {
                rsa.ImportParameters(privateKey);
                return rsa.Decrypt(data, RSAEncryptionPadding.Pkcs1);
            }
        }
    }
}
