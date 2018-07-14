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

```xml
<?xml version="1.0" encoding="utf-8"?>
<DualLayerEncryptionPackage xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <EncryptedKey>cZAkja6eJBu1ENvz2UXsfkD96xi7LHM9Jv6O6amBYDrTu0/GX0NcPaBSu/nIzDWy3ns7rDcI+TgN7ovPxB0FWIK937SLud9AUZ4FP1PQ6AwuK4LQTTL/oT7k/XI2Fjzc7taCoky1eGZBi7Hw7j30nCtKsLWY/JCOF7r407wZ6gmxR8QYG6+SOxy/7a4J+TTKaqEmiMyOGyyu5D1aXGDvTPSacwraH1VAEziSHTbazQUY9rua4s2jSkfvSmEfxu0muo4uKx9ZP9c1OASQ370Duz/kGzNWM2wAKBvCY540UI9D7g3XdBmTffbaaEv1iPgTAb9oi5pNn/DePk2e18ZFHf3nCeOH6uygEE7g9uWkxwvkD/mdP2n4Sf78Z+sLImzukVFpt8uRPkCEk+v4qQmmCxuGCtC9lZ62lGNFs+fq0tl+okUxEMeQbEHykJDPzbbJ1dpFheNCBt1hzqR5Jr1Dd5PNQqncAvc3Ff5cLcKfKSMznEfLjGooUFCnQt6OtOHXm+C+HhzU3CYb2W8er/cw7+FZcviHHDSQRPgcub+tumzvA8DvQOijYfChm+XnDIawPyzcYYrRZWSKUU1Hz1REpyoavMcOcuwkvySh9Nim92sx+a0IzhSwLkuPxwu4bvZ/vGaak7ffqe5QyXZxCEWEA+4eXHPpXjQI4tXcJxzNrE0=</EncryptedKey>
  <EncryptedMessage>3IXXfgjKJUsKndhLlK3BdQ==</EncryptedMessage>
</DualLayerEncryptionPackage>
```
