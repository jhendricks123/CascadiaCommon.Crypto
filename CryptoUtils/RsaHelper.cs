using System.Security.Cryptography;

namespace CascadiaCommon.Crypto
{
    public class RsaHelper
    {
        public RSACryptoServiceProvider CryptoServiceProvider => _rsaCsp;

        public string PublicPrivateKeyValue => _rsaCsp.ToXmlString(true);

        public string PublicKeyValue => _rsaCsp.ToXmlString(false);

        private readonly RSACryptoServiceProvider _rsaCsp;

        private RsaHelper(RSACryptoServiceProvider rsaCsp)
        {
            _rsaCsp = rsaCsp;
        }

        public static RsaHelper Create(int keySize)
        {
            return new RsaHelper(new RSACryptoServiceProvider(keySize));
        }

        public static RsaHelper Create(string rsaKeyValue)
        {
            var rsa = new RSACryptoServiceProvider();
            rsa.FromXmlString(rsaKeyValue);
            return new RsaHelper(rsa);
        }

        public byte[] Encrypt(byte[] data)
        {
            return _rsaCsp.Encrypt(data, false);
        }

        public byte[] Decrypt(byte[] data)
        {
            return _rsaCsp.Decrypt(data, false);
        }
    }
}