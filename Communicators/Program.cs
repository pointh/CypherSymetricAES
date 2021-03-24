using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace Communicators
{
    struct Zprava
    {
        public Communicator odesilatel;
        public string zasifrovanaZprava;
        public byte[] iv;
        public CipherMode mode;

        public override string ToString()
        {
            return zasifrovanaZprava;
        }
    }

    class Communicator
    {
        // tyto 3 informace jsou dostupné ostatním komunikátorům
        public string Identifikator;                            // čitelná identifikakce komunikátora
        public RSAParameters publicKey;                         // veřejný klíč, aby nám ostatní mohli posílat RSA zašifrované zprávy
        public List<Zprava> messagesIn = new List<Zprava>();    // message box, do kterého přijímáme zprávy

        private List<Zprava> messagesOut = new List<Zprava>();
        private const int keySize = 2048; // velikost klíče pro asymetrické šifrování - velmi bezpečné!
        private byte[] klic;
        private RSAParameters privateKey;
        private Dictionary<Communicator, byte[]> keyChain = new Dictionary<Communicator, byte[]>();

        public Communicator(string name)
        {
            this.Identifikator = name;
            klic = new byte[256 / 8]; // prázdný
            RandomNumberGenerator.Create().GetBytes(klic);  // generuj symetrický klíč - zaplň pole
            keyChain[this] = klic;

            using (var rsa = RSA.Create()) // generuj klíče pro přenos symetrickéko klíče
            {
                rsa.KeySize = keySize; ;
                publicKey = rsa.ExportParameters(includePrivateParameters: false);
                privateKey = rsa.ExportParameters(includePrivateParameters: true);
            }
        }

        private void ShareKeyWith(Communicator receiver)
        {
            #region Šifrování přenosu
            byte[] encryptedSymetricKey;
            using (var rsa = RSA.Create())
            {
                rsa.ImportParameters(receiver.publicKey);  // šifrujeme cizím veřejným klíčem
                encryptedSymetricKey = rsa.Encrypt(keyChain[this], RSAEncryptionPadding.Pkcs1);
            }
            #endregion
            receiver.ReceiveKey(this, encryptedSymetricKey);    // ---> odesílání zašifrovaného sym. klíče
        }

        private void ReceiveKey(Communicator from, byte[] encryptedSymetricKey)
        {
            #region Dešifrováná přenosu
            byte[] decryptedSymetricKey;
            using (var rsa = RSA.Create())
            {
                rsa.ImportParameters(privateKey);   // dešifrujeme vlastním privátním klíčem
                                                    // který je propojený s vlastním veřejným klíčem
                decryptedSymetricKey = rsa.Decrypt(encryptedSymetricKey, RSAEncryptionPadding.Pkcs1);
            }
            #endregion
            keyChain[from] = decryptedSymetricKey;  // uložení dešifrovaného sym. klíče
        }

        public void Send(string otevrenaZprava, Communicator receiver)
        {
            byte[] zpravaBytes = Encoding.GetEncoding("UTF-16").GetBytes(otevrenaZprava); // GetBytes, GetString - komplementární
            byte[] inicializacniVektor; // to nám vytvoří šifrování a předáme jej pro dešifrování - neutajujeme
            byte[] sifrovanaZpravaBytes;

            Zprava zprava;
            zprava.odesilatel = this;

            using (var aes = Aes.Create())
            {
                aes.Mode = CipherMode.CBC;
                aes.Key = klic;
                aes.GenerateIV();
                inicializacniVektor = aes.IV; // pro každou komunikaci se vytváří nový IV, klic zustava stejny, utajovaný - nepřenáší se

                using (var sifrator = aes.CreateEncryptor())
                {
                    sifrovanaZpravaBytes = sifrator.TransformFinalBlock(zpravaBytes, 0, zpravaBytes.Length);
                    zprava.zasifrovanaZprava = Convert.ToBase64String(sifrovanaZpravaBytes);
                    zprava.iv = inicializacniVektor;
                    zprava.mode = aes.Mode;
                }
            }
            this.messagesOut.Add(zprava);   // umístíme zašifrovanou zprávu do vstupní fronty příjemce
            Console.WriteLine(zprava);
            ShareKeyWith(receiver);         // pošleme příjemci klíč pro dešifrování, ale klíč zašifrujeme veřejným klíčem adresáta
            receiver.messagesIn.Add(zprava);
        }

        public void DecodeFrom(Communicator sender = null) // null = dekóduj od všech
        {
            IEnumerable<Zprava> dosleZpravyFromSender;

            if (sender != null)
                dosleZpravyFromSender = messagesIn.Where((t) => t.odesilatel == sender);
            else
                dosleZpravyFromSender = messagesIn;


            foreach (Zprava zprava in dosleZpravyFromSender)
            {
                byte[] klic = keyChain[zprava.odesilatel];

                if (klic == null)
                {
                    Console.WriteLine("Klič pro zprávu nenalezen");
                    return;
                }

                string desifrovanaZprava;
                using (var aes = Aes.Create())
                {
                    aes.Key = klic;
                    aes.IV = zprava.iv;
                    aes.Mode = zprava.mode;

                    using (var desifrator = aes.CreateDecryptor())
                    {
                        byte[] zasifrovanaZpravaBytes = Convert.FromBase64String(zprava.zasifrovanaZprava);
                        byte[] desifrovanaZpravaBytes = desifrator.TransformFinalBlock(zasifrovanaZpravaBytes,
                            0, zasifrovanaZpravaBytes.Length);
                        desifrovanaZprava = Encoding.GetEncoding("UTF-16").GetString(desifrovanaZpravaBytes);
                    }
                }
                Console.WriteLine($"Zpráva pro {Identifikator} od {zprava.odesilatel.Identifikator}: {desifrovanaZprava}");
            }
        }
    }

    class Program
    {
        static void Main(string[] args)
        {
            Communicator A = new Communicator("Antonín");
            Communicator B = new Communicator("Běta");
            A.Send("Zase schůze", B);
            A.Send("Nekončící", B);
            B.Send("Sám sobě", B);
            B.Send("Nespi", A);
            B.DecodeFrom(A);
            A.DecodeFrom();
            Console.ReadLine();
        }
    }
}
