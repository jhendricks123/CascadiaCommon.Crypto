using System;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using System.Xml.Serialization;

namespace CascadiaCommon.Crypto
{
    public class AesHelper
    {
        public AesCryptoServiceProvider CryptoServiceProvider => _aesCsp;
        public AesKeyInfo KeyInfo { get; private set; }
        private readonly AesCryptoServiceProvider _aesCsp;

        private AesHelper(AesCryptoServiceProvider aesCsp)
        {
            _aesCsp = aesCsp;
            KeyInfo = new AesKeyInfo {IV = _aesCsp.IV, Key = _aesCsp.Key};
        }

        public static AesHelper Create(int keySize)
        {
            var aesCsp = new AesCryptoServiceProvider() {KeySize = keySize};
            aesCsp.GenerateIV();
            aesCsp.GenerateKey();
            return new AesHelper(aesCsp);
        }

        public static AesHelper Create(AesKeyInfo keyInfo)
        {
            var aesCsp = new AesCryptoServiceProvider() { Key = keyInfo.Key, IV = keyInfo.IV };
            return new AesHelper(aesCsp);
        }

        public byte[] Encrypt(byte[] data)
        {
            using (var memoryStream = new MemoryStream())
            {
                using (var cryptoStream =
                    new CryptoStream(memoryStream, _aesCsp.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    cryptoStream.Write(data, 0, data.Length);
                }
                return memoryStream.ToArray();
            }
        }

        public byte[] Decrypt(byte[] data)
        {
            using (var srcMemStream = new MemoryStream(data))
            {
                using (var cryptoStream =
                    new CryptoStream(srcMemStream, _aesCsp.CreateDecryptor(), CryptoStreamMode.Read))
                using (var dstMemStream = new MemoryStream())
                {
                    cryptoStream.CopyTo(dstMemStream);
                    return dstMemStream.ToArray();
                }
            }
        }

        [Serializable]
        [SuppressMessage("ReSharper", "InconsistentNaming")]
        public struct AesKeyInfo
        {
            public byte[] Key { get; set; }
            public byte[] IV { get; set; }

            public string ToXmlString()
            {
                var serializer = new XmlSerializer(typeof(AesKeyInfo));
                using (var memoryStream = new MemoryStream())
                using (var writer = new StreamWriter(memoryStream))
                {
                    serializer.Serialize(writer, this);
                    return Encoding.UTF8.GetString(memoryStream.ToArray());
                }
            }

            public static AesKeyInfo FromXmlString(string xml)
            {
                var serializer = new XmlSerializer(typeof(AesKeyInfo));
                using (var memoryStream = new MemoryStream(Encoding.UTF8.GetBytes(xml)))
                {
                    using (var xmlReader = XmlReader.Create(memoryStream))
                    {
                        return (AesKeyInfo)serializer.Deserialize(xmlReader);
                    }
                    
                }
            }
        }
    }
}