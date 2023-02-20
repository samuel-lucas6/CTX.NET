/*
    CTX.NET: Chan and Rogaway's fully committing AEAD construction using ChaCha20-Poly1305 and BLAKE2b-160.
    Copyright (c) 2022-2023 Samuel Lucas
    
    Permission is hereby granted, free of charge, to any person obtaining a copy of
    this software and associated documentation files (the "Software"), to deal in
    the Software without restriction, including without limitation the rights to
    use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
    the Software, and to permit persons to whom the Software is furnished to do so,
    subject to the following conditions:
    
    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.
    
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
*/

using System.Security.Cryptography;
using System.Buffers.Binary;
using Geralt;
using ChaCha20Poly1305 = Geralt.ChaCha20Poly1305;

namespace CTXDotNet;

public static class CTX
{
    public const int KeySize = ChaCha20Poly1305.KeySize;
    public const int NonceSize = ChaCha20Poly1305.NonceSize;
    public const int TagSize = 20;
    private const int AlignSize = 16;
    
    public static void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        Validation.EqualToSize(nameof(ciphertext), ciphertext.Length, plaintext.Length + TagSize);
        
        Span<byte> ciphertextCore = ciphertext[..^(TagSize - Poly1305.TagSize)];
        ChaCha20Poly1305.Encrypt(ciphertextCore, plaintext, nonce, key, associatedData);
        
        using var blake2b = new IncrementalBLAKE2b(TagSize, key);
        blake2b.Update(nonce);
        blake2b.Update(associatedData);
        blake2b.Update(ciphertextCore[^Poly1305.TagSize..]);
        blake2b.Finalize(ciphertext[^TagSize..]);
    }
    
    public static void Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        Validation.NotLessThanMin(nameof(ciphertext), ciphertext.Length, TagSize);
        Validation.EqualToSize(nameof(plaintext), plaintext.Length, ciphertext.Length - TagSize);
        
        Span<byte> block0 = stackalloc byte[ChaCha20.BlockSize];
        ChaCha20.Fill(block0, nonce, key);
        Span<byte> macKey = block0[..Poly1305.KeySize];
        
        Span<byte> tag = stackalloc byte[Poly1305.TagSize];
        ReadOnlySpan<byte> ciphertextNoTag = ciphertext[..^TagSize];
        ComputeTag(tag, associatedData, ciphertextNoTag, macKey);
        CryptographicOperations.ZeroMemory(block0);
        
        Span<byte> tagHash = stackalloc byte[TagSize];
        using var blake2b = new IncrementalBLAKE2b(tagHash.Length, key);
        blake2b.Update(nonce);
        blake2b.Update(associatedData);
        blake2b.Update(tag);
        blake2b.Finalize(tagHash);
        CryptographicOperations.ZeroMemory(tag);
        
        bool valid = ConstantTime.Equals(tagHash, ciphertext[^TagSize..]);
        CryptographicOperations.ZeroMemory(tagHash);
        
        if (!valid) {
            throw new CryptographicException();
        }
        
        ChaCha20.Decrypt(plaintext, ciphertextNoTag, nonce, key, counter: 1);
    }
    
    private static void ComputeTag(Span<byte> tag, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> macKey)
    {
        Span<byte> padding1 = stackalloc byte[Align(associatedData.Length, AlignSize)];
        Span<byte> padding2 = stackalloc byte[Align(ciphertext.Length, AlignSize)];
        padding1.Clear(); padding2.Clear();
        
        Span<byte> associatedDataLength = stackalloc byte[sizeof(ulong)], ciphertextLength = stackalloc byte[sizeof(ulong)];
        BinaryPrimitives.WriteUInt64LittleEndian(associatedDataLength, (ulong)associatedData.Length);
        BinaryPrimitives.WriteUInt64LittleEndian(ciphertextLength, (ulong)ciphertext.Length);
        
        using var poly1305 = new IncrementalPoly1305(macKey);
        poly1305.Update(associatedData);
        poly1305.Update(padding1);
        poly1305.Update(ciphertext);
        poly1305.Update(padding2);
        poly1305.Update(associatedDataLength);
        poly1305.Update(ciphertextLength);
        poly1305.Finalize(tag);
    }
    
    private static int Align(int x, int pow2)
    {
        return (~x + 1) & (pow2 - 1);
    }
}