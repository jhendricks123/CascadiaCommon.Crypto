using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Linq;
using System.Text;

// ReSharper disable once CheckNamespace
namespace CascadiaCommon.Crypto.Tests
{
    [TestClass()]
    public class AesHelperTests
    {
        [TestMethod()]
        public void DecryptTest_EncryptedMessageMatchesDecryptedMessage()
        {
            var helper = AesHelper.Create(256);
            var originalMessage = Encoding.UTF8.GetBytes("Hello world!");
            var encryptedMessage = helper.Encrypt(originalMessage);
            var decryptedMessage = helper.Decrypt(encryptedMessage);
            Assert.IsTrue(originalMessage.SequenceEqual(decryptedMessage));
        }

        [TestMethod()]
        public void DecryptTest_ReusedKeyEncryptedMessageMatchesDecryptedMessage()
        {
            var helper1 = AesHelper.Create(256);
            var helper2 = AesHelper.Create(helper1.KeyInfo);

            var originalMessage = Encoding.UTF8.GetBytes("Hello world!");
            var encryptedMessage = helper1.Encrypt(originalMessage);
            var decryptedMessage = helper2.Decrypt(encryptedMessage);
            Assert.IsTrue(originalMessage.SequenceEqual(decryptedMessage));
        }
    }
}