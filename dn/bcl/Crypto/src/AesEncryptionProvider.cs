using System.Security.Cryptography;

namespace FrostYeti.Crypto;

/// <summary>
/// Provides AES CBC encryption and decryption capabilities. By default,
/// it uses a 256-bit key size.
/// </summary>
/// <remarks>
///  <para>
///   The provider takes the pain out of properly encrypting and decrypting data using AES-256
///   by always using a secure key derivation function (PBKDF2) to derive the encryption key,
///   and correctly generating a unique nonce (IV), and salt for each encryption operation.
///  </para>
///  <para>
///   The provider also includes a message authentication code (MAC) to ensure the integrity
///   of the encrypted data, which defaults to HMAC-SHA256.
///  </para>
///  <para>
///    The encrypted data includes a header that contains metadata about the encryption,
///    such as the version, metadata size, iterations, salt size, tag salt size, etc.
///  </para>
///  <list type="number">
///    <item>version (short)</item>
///    <item>salt size (short)</item>
///    <item>key size (short)</item>
///    <item>PBKDF2 hash algorithm (short)</item>
///    <item>tag hash type (short)</item>
///    <item>tag salt size (short)</item>
///    <item>metadata size (int)</item>
///    <item>iterations (int)</item>
///    <item>salt (byte[])</item>
///    <item>IV (byte[])</item>
///    <item>HMAC salt (byte[])</item>
///   <item>metadata (byte[])</item>
///   <item>HMAC (byte[])</item>
///   <item>encrypted data (byte[])</item>
///  </list>
/// </remarks>
public class AesEncryptionProvider : IEncryptionProvider
{
    private readonly AesEncryptionProviderOptions options;

    public AesEncryptionProvider(AesEncryptionProviderOptions options)
    {
        this.options = options;
    }

    public byte[] Encrypt(byte[] data)
    {
        var span = this.Encrypt(data, this.options.Key, Array.Empty<byte>());
        return span.ToArray();
    }

    public ReadOnlySpan<byte> Encrypt(ReadOnlySpan<byte> data)
    {
        return this.Encrypt(data, this.options.Key, Array.Empty<byte>());
    }

    public ReadOnlySpan<byte> Encrypt(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key, ReadOnlySpan<byte> metadata)
    {
        if (key.IsEmpty && this.options.Key.Length == 0)
            throw new ArgumentException("Encryption key is empty.", nameof(key));

        if (key.IsEmpty)
        {
            key = this.options.Key;
        }

        using var header = AesEncryptionHeaderV1.CreateFromOptions(this.options, metadata.Length);
        byte[] encryptedBlob;

        using var aes = CreateAesFromHeader(header, this.options.KeySize, key);
        using var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
        using var ms = new MemoryStream();
        using var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write);
        cs.Write(data);
        cs.Flush();
        cs.FlushFinalBlock();
        ms.Flush();
        encryptedBlob = ms.ToArray();

        var result = new byte[header.Size + header.MetaDataSize + header.TagHash.Size + encryptedBlob.Length];
        int index = 0;
        header.Bytes.CopyTo(result.AsSpan(index));
        index += header.Size;

        if (metadata.Length > 0)
        {
            metadata.CopyTo(result.AsSpan(index));
            index += header.MetaDataSize;
        }

        var hashKey = Rfc2898DeriveBytes.Pbkdf2(
            key,
            header.TagSalt,
            header.Iterations,
            header.TagHash,
            header.TagHash.Size);

        using var hasher = header.TagHash.CreateHmac(hashKey);

        // use hasher.TryComputeHash to avoid allocating a new array
        if (!hasher.TryComputeHash(encryptedBlob, result.AsSpan(index), out var bytesWritten) || bytesWritten != header.TagHash.Size)
        {
            Array.Clear(hashKey, 0, hashKey.Length);
            Array.Clear(encryptedBlob, 0, encryptedBlob.Length);
            throw new CryptographicException("Failed to compute hash.");
        }

        Array.Clear(hashKey, 0, hashKey.Length);

        index += header.TagHash.Size;
        encryptedBlob.CopyTo(result.AsSpan(index));

        Array.Clear(hashKey, 0, hashKey.Length);
        Array.Clear(encryptedBlob, 0, encryptedBlob.Length);

        return result;
    }

    public byte[] Decrypt(byte[] encryptedData)
    {
        var span = this.Decrypt(encryptedData.AsSpan(), this.options.Key, Array.Empty<byte>(), out _);
        return span.ToArray();
    }

    public ReadOnlySpan<byte> Decrypt(ReadOnlySpan<byte> data)
    {
        return this.Decrypt(data, this.options.Key, Array.Empty<byte>(), out _);
    }

    public ReadOnlySpan<byte> Decrypt(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key, Span<byte> metaData, out int metaDataLength)
    {
        metaDataLength = 0;
        if (key.IsEmpty && this.options.Key.Length == 0)
            throw new ArgumentException("Encryption key is empty.", nameof(key));

        if (key.IsEmpty)
        {
            key = this.options.Key;
        }

        using var header = AesEncryptionHeaderV1.ReadFromData(data);

        var encryptedMessage = data.ToArray();

        var index = header.Size;

        if (header.MetaDataSize > 0)
        {
            metaDataLength = header.MetaDataSize;
            var actualMetaData = data.Slice(index, header.MetaDataSize);
            var length = Math.Min(metaData.Length, actualMetaData.Length);
            actualMetaData.Slice(0, length).CopyTo(metaData);
            index += header.MetaDataSize;
        }

        var tag = data.Slice(index, header.TagHash.Size);
        index += header.TagHash.Size;

        var hashKey = Rfc2898DeriveBytes.Pbkdf2(
            key,
            header.TagSalt,
            header.Iterations,
            header.TagHash,
            header.TagHash.Size);

        var hashSize = header.TagHash.Size;
        var encryptedBlob = data.Slice(index);

        using var hasher = header.TagHash.CreateHmac(hashKey);

        // use hasher.TryComputeHash to avoid allocating a new array
        var hash = new byte[hashSize];
        if (!hasher.TryComputeHash(encryptedBlob, hash, out var bytesWritten) || bytesWritten != hashSize)
        {
            Array.Clear(hash, 0, hash.Length);
            Array.Clear(encryptedBlob.ToArray(), 0, encryptedBlob.Length);
            throw new CryptographicException("Failed to compute hash.");
        }

        Array.Clear(hashKey, 0, hashKey.Length);
        if (!tag.SlowEquals(hash))
        {
            throw new CryptographicException("Hashes do not match.");
        }

        Array.Clear(hash, 0, hash.Length);

        using var aes = CreateAesFromHeader(header, this.options.KeySize, key);
        using var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
        using var ms2 = new MemoryStream();
        using var cs = new CryptoStream(ms2, decryptor, CryptoStreamMode.Write);

        cs.Write(encryptedBlob);
        cs.Flush();
        cs.FlushFinalBlock();
        ms2.Flush();
        return ms2.ToArray();
    }

    private static Aes CreateAesFromHeader(AesEncryptionHeaderV1 header, short keySize, ReadOnlySpan<byte> key)
    {
        var aes = Aes.Create();
        aes.Padding = PaddingMode.PKCS7;
#pragma warning disable SCS0013 // Weak Cipher Mode is mitigated by the use of a Message Authentication Code.
        aes.Mode = CipherMode.CBC;
#pragma warning restore SCS0013
        aes.IV = header.IV;

        var ks = keySize * 8;
        if (ks != 256 && ks != 128 && ks != 192)
            throw new ArgumentException("Key size must be either 128, 192, or 256 bits.", nameof(keySize));

        aes.KeySize = keySize * 8; // Convert to bits

        aes.Key = Rfc2898DeriveBytes.Pbkdf2(
            key,
            header.Salt,
            header.Iterations,
            header.Hash,
            keySize); // 256 bits = 32 bytes

        return aes;
    }
}