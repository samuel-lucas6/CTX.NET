using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Security.Cryptography;
using CTXDotNet;

namespace CTXDotNetTests;

[TestClass]
public class CTXTests
{
    public static IEnumerable<object[]> TestVectors()
    {
        yield return new object[]
        {
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116a7c38858c8387c1035f2df946991f5cf2e77ac85",
            "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
            "070000004041424344454647",
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            "50515253c0c1c2c3c4c5c6c7"
        };
    }
    
    public static IEnumerable<object[]> InvalidParameterSizes()
    {
        yield return new object[] { CTX.TagSize - 1, 0, CTX.NonceSize, CTX.KeySize, CTX.TagSize };
        yield return new object[] { CTX.TagSize, 1, CTX.NonceSize, CTX.KeySize, CTX.TagSize };
        yield return new object[] { CTX.TagSize, 0, CTX.NonceSize + 1, CTX.KeySize, CTX.TagSize };
        yield return new object[] { CTX.TagSize, 0, CTX.NonceSize - 1, CTX.KeySize, CTX.TagSize };
        yield return new object[] { CTX.TagSize, 0, CTX.NonceSize, CTX.KeySize + 1, CTX.TagSize };
        yield return new object[] { CTX.TagSize, 0, CTX.NonceSize, CTX.KeySize - 1, CTX.TagSize };
    }
    
    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Encrypt_Valid(string ciphertext, string plaintext, string nonce, string key, string associatedData)
    {
        Span<byte> p = Convert.FromHexString(plaintext);
        Span<byte> c = stackalloc byte[p.Length + CTX.TagSize];
        Span<byte> n = Convert.FromHexString(nonce);
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> a = Convert.FromHexString(associatedData);
        
        CTX.Encrypt(c, p, n, k, a);
        
        Assert.AreEqual(ciphertext, Convert.ToHexString(c).ToLower());
    }
    
    [TestMethod]
    [DynamicData(nameof(InvalidParameterSizes), DynamicDataSourceType.Method)]
    public void Encrypt_Invalid(int ciphertextSize, int plaintextSize, int nonceSize, int keySize, int associatedDataSize)
    {
        var c = new byte[ciphertextSize];
        var p = new byte[plaintextSize];
        var n = new byte[nonceSize];
        var k = new byte[keySize];
        var a = new byte[associatedDataSize];
        
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => CTX.Encrypt(c, p, n, k, a));
    }
    
    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Decrypt_Valid(string ciphertext, string plaintext, string nonce, string key, string associatedData)
    {
        Span<byte> c = Convert.FromHexString(ciphertext);
        Span<byte> p = stackalloc byte[c.Length - CTX.TagSize];
        Span<byte> n = Convert.FromHexString(nonce);
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> a = Convert.FromHexString(associatedData);
        
        CTX.Decrypt(p, c, n, k, a);
        
        Assert.AreEqual(plaintext, Convert.ToHexString(p).ToLower());
    }
    
    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Decrypt_Tampered(string ciphertext, string plaintext, string nonce, string key, string associatedData)
    {
        var parameters = new List<byte[]>
        {
            Convert.FromHexString(ciphertext),
            Convert.FromHexString(nonce),
            Convert.FromHexString(key),
            Convert.FromHexString(associatedData)
        };
        var p = new byte[parameters[0].Length - CTX.TagSize];
        
        foreach (var param in parameters) {
            param[0]++;
            Assert.ThrowsException<CryptographicException>(() => CTX.Decrypt(p, parameters[0], parameters[1], parameters[2], parameters[3]));
            param[0]--;
        }
    }
    
    [TestMethod]
    [DynamicData(nameof(InvalidParameterSizes), DynamicDataSourceType.Method)]
    public void Decrypt_Invalid(int ciphertextSize, int plaintextSize, int nonceSize, int keySize, int associatedDataSize)
    {
        var c = new byte[ciphertextSize];
        var p = new byte[plaintextSize];
        var n = new byte[nonceSize];
        var k = new byte[keySize];
        var a = new byte[associatedDataSize];
        
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => CTX.Decrypt(p, c, n, k, a));
    }
}