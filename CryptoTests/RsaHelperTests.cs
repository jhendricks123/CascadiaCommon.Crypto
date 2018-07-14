using Microsoft.VisualStudio.TestTools.UnitTesting;
using CascadiaCommon.Crypto;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CascadiaCommon.Crypto.Tests
{
    [TestClass()]
    public class RsaHelperTests
    {
        [TestMethod()]
        public void Create_Makes_RsaCsp_With_Correct_KeySize_Test()
        {
            var keySize = 1024;
            var helper = RsaHelper.Create(keySize);
            Assert.AreEqual(helper.CryptoServiceProvider.KeySize, keySize);
        }

        [TestMethod()]
        public void EncryptTest_DontThrowException()
        {
            var helper = RsaHelper.Create(1024);
            var data = helper.Encrypt(Encoding.UTF8.GetBytes("Hello world!"));

            Assert.IsTrue(data?.Length > 0);
        }

        [TestMethod()]
        public void DecryptTest_EncryptedMessageMatchesDecryptedMessage()
        {
            var message = "Hello world!";
            var helper = RsaHelper.Create(1024);
            var encryptedMessage = helper.Encrypt(Encoding.UTF8.GetBytes(message));
            var message2 = Encoding.UTF8.GetString(helper.Decrypt(encryptedMessage));
            Assert.AreEqual(message, message2);
        }

        [TestMethod()]
        public void DecryptTest_ReusedKeyEncryptedMessageMatchesDecryptedMessage()
        {
            var publicKeyXml = @"<RSAKeyValue><Modulus>5u+S1Yt7LZsoeUxUGiDpH/RYD8Ms3yjbJ/fh0qHbciuKVqtyvMPMQRRnCfHMGzJjVW0JuEsYM6FVv59RgTD/44RlJ1uEasRBVnl05MaSos7yjx4dNipRBL5XuOvhiPzlmgOyznLAXsXN/tMYNydGaqryPefmjnbdenzXSPutjJE=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";
            var privateKeyXml = @"<RSAKeyValue><Modulus>5u+S1Yt7LZsoeUxUGiDpH/RYD8Ms3yjbJ/fh0qHbciuKVqtyvMPMQRRnCfHMGzJjVW0JuEsYM6FVv59RgTD/44RlJ1uEasRBVnl05MaSos7yjx4dNipRBL5XuOvhiPzlmgOyznLAXsXN/tMYNydGaqryPefmjnbdenzXSPutjJE=</Modulus><Exponent>AQAB</Exponent><P>9BmI+4NY/+E9KACztjnulpCuvh2RhYCI7P/Ra8jSk8gfbF3Hq8nHOH9VKQDL6l3R7jbPUaKrNeWYJVWLAmzBcw==</P><Q>8jG/Wa8+DyAUvhoFwkCYxGIOkN6bQZhC0N+rsAlGvW/D1yJUkR4gtoH2wRXjVAdiVTAA4p/OMKaP2Dj2Lmoo6w==</Q><DP>NG9fy5d1gNHjjzpHYHelVtaRkulLH0BzKWXymJK1GWW9ykuC3tYjY3GG253+L8QjmmZPtpuY56UAP9TWXZj7HQ==</DP><DQ>tTEunOQUI7C2k/pX8JnvMIzDpPJFaO+GnUmY4pwuBi+Fbn/KkL7fbmsQtiev6P+VO3IsV1+DHLafyv3if5sAfQ==</DQ><InverseQ>HcJRsdt7Gyuvo68dv8vrwKgOQ0aydKSS5/lRCOQmHbMPyKG0YUZ/0x5/3S6L0kq/EJ5BrNNHX2I1yS0yUskl4g==</InverseQ><D>yG8swR0TZwzgvw6pfBgOXkaj2+JpYrLCK9lwbXE/1sLFid26cu15rQ55M99iaER+hJljs0myErW3h95OTlPp8rdW+wQwJxCMJKyDuUxJjiJK6Z3drZkpJggrUraNfz3BQvljxtsHKnXaKnojcwOD3MVX9XnSMtn7yx9gWs/JI/U=</D></RSAKeyValue>";

            var publicRsaHelper = RsaHelper.Create(publicKeyXml);
            var privateRsaHelper = RsaHelper.Create(privateKeyXml);

            var originalMessage = Encoding.UTF8.GetBytes("Hello world!");
            var encryptedMessage = publicRsaHelper.Encrypt(originalMessage);
            var decryptedMessage = privateRsaHelper.Decrypt(encryptedMessage);

            Assert.IsTrue(originalMessage.SequenceEqual(decryptedMessage));
        }
    }
}