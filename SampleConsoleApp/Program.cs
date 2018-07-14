using CascadiaCommon.Crypto;
using System;
using System.Text;

namespace SampleConsoleApp
{
    internal class Program
    {
        internal static void Main(string[] args)
        {
            // Create private/public key pair and save the XML representation of the keys for later.
            // Normally these keys would already exist and be loaded at runtime, but are created here
            // for demo purposes.
            var tempRsaHelper = RsaHelper.Create(4096);
            var publicKey = tempRsaHelper.PublicKeyValue;
            var privateKey = tempRsaHelper.PublicPrivateKeyValue;

            // Demo combines both client and server. Here we instantiate the client/server RsaHelpers 
            // with the appropriate key info. Do NOT include the private key anywhere in client-side code
            // unless you intend to send data back to the client to decode.
            var clientSideRsaHelper = RsaHelper.Create(publicKey);
            var serverSideRsaHelper = RsaHelper.Create(privateKey);

            // Instantiate the encryptor objects used to create, and decrypt the serialized XML
            // representation of the data.
            var clientSideDualLayerEncryptor = DualLayerEncryptor.Create(clientSideRsaHelper);
            var serverSideDualLayerEncryptor = DualLayerEncryptor.Create(serverSideRsaHelper);

            var messageData = Encoding.UTF8.GetBytes("Hello world!");

            // Encrypt the message and generate serialized XML package containing the base64
            // encoded strings representing the RSA encrypted AES key info, and the AES 
            // encrypted message
            var encryptedDataXml = clientSideDualLayerEncryptor.Encrypt(messageData);

            // Take the XML data, decrypt the AES key info, decrypt the AES encrypted message and
            // return the resulting byte[] which should exactly match the original byte[]
            var decryptedData = serverSideDualLayerEncryptor.Decrypt(encryptedDataXml);

            Console.WriteLine(Encoding.UTF8.GetString(decryptedData));
            
            Console.ReadKey();
        }
    }
}
