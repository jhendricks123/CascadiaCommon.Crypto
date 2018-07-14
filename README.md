# CascadiaCommon.Crypto

Helper classes for working with AES and RSA crypto service providers, and a wrapper for implementing SSL/TLS style encryption whereby the data is encrypted using symmetrical AES encryption and the random AES key info is encrypted using asymmetrical RSA encryption.

I created this because I had a need for keeping some data secure "at rest", and decrypting it later from a different computer.

## Getting Started

The main objects are the RsaHelper, AesHelper, and the DualLayerEncryptor which uses both AES and RSA encryption to encrypt messages that are too large for RSA encryption alone.

The SampleConsoleApp project walks through instantiating the helper classes, and using the DualLayerEncryptor object to encrypt/decrypt data.


```C#
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

```


## What does the serialized encrypted data from the DualLayerEncryptor look like

'''
<?xml version="1.0" encoding="utf-8"?>
<DualLayerEncryptionPackage xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
	<EncryptedKey>Ay8UXIDk2BbBgPoiBNqbF5wA8fFXwf/A+AMG2gvAyxOoJASdhTuw4d/b+Gw8iCEuzssmCLvIWr3idjOgv+WURzmPtflyUnwMhFlt177cqAskqzYDJOGTBs+3dpOQRXG+eoBNrZaBl/YfxA/y8GFPmbOMeo8fwQW/374FuRWKhVcEqDyGtSdBcpD8+vWBDto88nJOmkxgdciH5j4hm/y33faKtIz8LTrYy7a0lS+j7OxZcnNg8R2TLLd68+NhfrxGSHE/uVUZ7MkAW3r14mzmGrK+Icowj/CHbwdBB8PI20mfdaLqYQK+CE9PDX8uwDDVpmpe5IWf9By7chLcx6fkIEYtSCj99jMC1+q64LeYQIloXeCm/dTWuligQ5y1NxOCv2LM63INE6b2IUKehRcr+oChgsyIJ0X6VAgrfh+zAULKR7xNKDn9CnCWQ3h0hmb/Uecz4NYWhFCu1HJSAhkkuGcyG23EPm2xIqg10zx7bRYk//hPDVPEzHgQe6nC18WEbgsCmgCGEvQIaPSRMYqUlTJO4oy35xQPZBa5N8l+ADVKUlRYVuJ/hN2wVi37XrrDZePmWEB7ZmhLWa4J5CWMonmKfnIxuBlEp3s+nPkUZTrHe7fDCd0fir5dSlrBvJf4QPL0vBEvRO0T1s2PUSGCsJG7WhPSKffvoM04zT26v2A=</EncryptedKey>
	<EncryptedMessage>6uVYLq6Qh0lEQQ1HNcNkCw==</EncryptedMessage>
</DualLayerEncryptionPackage>
'''
