using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Security.Cryptography;
using CTXConstruction;

namespace CTXConstructionTests;

[TestClass]
public class CTXTests
{
    private static readonly byte[] Plaintext = Convert.FromHexString("4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e");
    private static readonly byte[] Nonce = Convert.FromHexString("070000004041424344454647");
    private static readonly byte[] Key = Convert.FromHexString("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    private static readonly byte[] AssociatedData = Convert.FromHexString("50515253c0c1c2c3c4c5c6c7");
    private static readonly byte[] Ciphertext = Convert.FromHexString("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116e5e6fb1862f83eb00da4562fe0496ed9253cfa7f");
    
    [TestMethod]
    public void Encrypt()
    {
        Span<byte> ciphertext = stackalloc byte[Plaintext.Length + CTX.TagSize];
        CTX.Encrypt(ciphertext, Plaintext, Nonce, Key, AssociatedData);
        Assert.IsTrue(ciphertext.SequenceEqual(Ciphertext));
    }
    
    [TestMethod]
    public void Decrypt()
    {
        Span<byte> plaintext = stackalloc byte[Plaintext.Length];
        CTX.Decrypt(plaintext, Ciphertext, Nonce, Key, AssociatedData);
        Assert.IsTrue(plaintext.SequenceEqual(Plaintext));
    }
    
    [TestMethod]
    public void DecryptWrongParameters()
    {
        var plaintext = new byte[Plaintext.Length];
        
        var wrongTag = Ciphertext.ToArray();
        wrongTag[^1]++;
        Assert.ThrowsException<CryptographicException>(() => CTX.Decrypt(plaintext, wrongTag, Nonce, Key, AssociatedData));
        
        var wrongCiphertext = Ciphertext.ToArray();
        wrongCiphertext[0]++;
        Assert.ThrowsException<CryptographicException>(() => CTX.Decrypt(plaintext, wrongCiphertext, Nonce, Key, AssociatedData));
        
        var wrongNonce = Nonce.ToArray();
        wrongNonce[0]++;
        Assert.ThrowsException<CryptographicException>(() => CTX.Decrypt(plaintext, Ciphertext, wrongNonce, Key, AssociatedData));
        
        var wrongKey = Key.ToArray();
        wrongKey[0]++;
        Assert.ThrowsException<CryptographicException>(() => CTX.Decrypt(plaintext, Ciphertext, Nonce, wrongKey, AssociatedData));
        
        var wrongAssociatedData = AssociatedData.ToArray();
        wrongAssociatedData[0]++;
        Assert.ThrowsException<CryptographicException>(() => CTX.Decrypt(plaintext, Ciphertext, Nonce, Key, wrongAssociatedData));
        Assert.ThrowsException<CryptographicException>(() => CTX.Decrypt(plaintext, Ciphertext, Nonce, Key));
        
        Assert.IsTrue(plaintext.SequenceEqual(new byte[plaintext.Length]));
    }
}