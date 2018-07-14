using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using System.Xml.Serialization;

namespace CascadiaCommon.Crypto
{
    public class DualLayerEncryptor
    {
        public int KeySize { get; set; } = 256;

        private readonly RsaHelper _rsaHelper;

        private DualLayerEncryptor(RsaHelper rsaHelper)
        {
            _rsaHelper = rsaHelper;
        }

        public string Encrypt(byte[] data)
        {
            var aesHelper = AesHelper.Create(KeySize);
            var encryptedData = aesHelper.Encrypt(data);
            var encryptedAesKey = _rsaHelper.Encrypt(Encoding.UTF8.GetBytes(aesHelper.KeyInfo.ToXmlString()));
            var package = new DualLayerEncryptionPackage(encryptedAesKey, encryptedData);
            return package.ToXmlString();
        }

        public byte[] Decrypt(string packageXml)
        {
            var package = DualLayerEncryptionPackage.FromXmlString(packageXml);
            var keyInfoXml = Encoding.UTF8.GetString(_rsaHelper.Decrypt(package.GetEncryptedKeyBytes()));
            var keyInfo = AesHelper.AesKeyInfo.FromXmlString(keyInfoXml);
            var aesHelper = AesHelper.Create(keyInfo);
            return aesHelper.Decrypt(package.GetEncryptedMessageBytes());
        }

        public static DualLayerEncryptor Create(RsaHelper rsaHelper)
        {
            return new DualLayerEncryptor(rsaHelper);
        }

        [Serializable]
        public struct DualLayerEncryptionPackage
        {
            public string EncryptedKey { get; set; }
            public string EncryptedMessage { get; set; }

            public DualLayerEncryptionPackage(byte[] keyBytes, byte[] messageBytes)
            {
                EncryptedKey = Convert.ToBase64String(keyBytes);
                EncryptedMessage = Convert.ToBase64String(messageBytes);
            }

            public byte[] GetEncryptedKeyBytes()
            {
                return Convert.FromBase64String(EncryptedKey);
            }

            public byte[] GetEncryptedMessageBytes()
            {
                return Convert.FromBase64String(EncryptedMessage);
            }

            public string ToXmlString()
            {
                var serializer = new XmlSerializer(typeof(DualLayerEncryptionPackage));
                using (var memoryStream = new MemoryStream())
                using (var writer = new StreamWriter(memoryStream))
                {
                    serializer.Serialize(writer, this);
                    return Encoding.UTF8.GetString(memoryStream.ToArray());
                }
            }

            public static DualLayerEncryptionPackage FromXmlString(string xml)
            {
                var serializer = new XmlSerializer(typeof(DualLayerEncryptionPackage));
                using (var memoryStream = new MemoryStream(Encoding.UTF8.GetBytes(xml)))
                {
                    using (var xmlReader = XmlReader.Create(memoryStream))
                    {
                        return (DualLayerEncryptionPackage)serializer.Deserialize(xmlReader);
                    }

                }
            }
        }
    }
}
