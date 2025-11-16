using System.Buffers.Binary;
using System.Security.Cryptography;

namespace FrostYeti.Crypto;

/// <summary>
/// The header for the AES256 encryption record.
/// </summary>
/// <remarks>
/// <list type="bullet">
///     <item>version</item>
///     <item>metadataSize</item>
///     <item>iterations</item>
///     <item>saltSize</item>
///     <item>hashSaltSize</item>
///     <item>ivSize</item>
///     <item>salt</item>
///     <item>hashSalt</item>
///     <item>iv</item>
/// </list>
/// </remarks>
internal sealed class AesEncryptionHeaderV1 : IDisposable
{
    public short Version { get; } = 1;

    public int MetaDataSize { get; set; }

    public short SaltSize { get; set; }

    public short TagSaltSize { get; set; }

    public byte[] Salt { get; set; } = Array.Empty<byte>();

    public byte[] TagSalt { get; set; } = Array.Empty<byte>();

    public Pbkdf2Hash Hash { get; set; } = Pbkdf2Hash.SHA256;

    public Pbkdf2Hash TagHash { get; set; } = Pbkdf2Hash.SHA256;

    // ReSharper disable once InconsistentNaming
    public byte[] IV { get; set; } = Array.Empty<byte>();

    public int Iterations { get; set; }

    public byte[] Bytes { get; set; } = Array.Empty<byte>();

    public int Size =>
      (sizeof(short) * 6) + (sizeof(int) * 2) + this.SaltSize + this.TagSaltSize + this.IV.Length;

    public static AesEncryptionHeaderV1 ReadFromData(ReadOnlySpan<byte> data)
    {
        // 1.  version  (short)
        // 2.  salt size (short)
        // 3.  key size (short)
        // 4.  pdk2 hash algorithm (short)
        // 5.  tag hash type (short)
        // 6.  tag salt size (short)
        // 7.  meta data size (int)
        // 8. iterations (int)
        // 9. salt (byte[])
        // 10. iv (byte[])
        // 11. tag salt (byte[])
        // 12. meta data (byte[])
        // 13. tag (byte[])
        // 13. encrypted data (byte[])
        var index = 0;
        var version = BinaryPrimitives.ReadInt16LittleEndian(data.Slice(index, sizeof(short)));
        if (version != 1)
            throw new InvalidOperationException($"Unsupported AES encryption header version: {version}");
        index += sizeof(short);

        var saltSize = BinaryPrimitives.ReadInt16LittleEndian(data.Slice(index, sizeof(short)));
        index += sizeof(short);

        var keySize = BinaryPrimitives.ReadInt16LittleEndian(data.Slice(index, sizeof(short)));
        index += sizeof(short);

        var hashAlgorithmId = BinaryPrimitives.ReadInt16LittleEndian(data.Slice(index, sizeof(short)));
        index += sizeof(short);

        var tagHashId = BinaryPrimitives.ReadInt16LittleEndian(data.Slice(index, sizeof(short)));
        index += sizeof(short);

        var tagSaltSize = BinaryPrimitives.ReadInt16LittleEndian(data.Slice(index, sizeof(short)));
        index += sizeof(short);

        var metaDataSize = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(index, sizeof(int)));
        index += sizeof(int);

        var iterations = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(index, sizeof(int)));
        index += sizeof(int);

        var salt = data.Slice(index, saltSize).ToArray();
        index += saltSize;

        var iv = data.Slice(index, 16).ToArray();
        index += 16;

        var tagSalt = data.Slice(index, tagSaltSize).ToArray();
        index += tagSaltSize;

        return new AesEncryptionHeaderV1()
        {
            SaltSize = saltSize,
            TagSaltSize = tagSaltSize,
            MetaDataSize = metaDataSize,
            Iterations = iterations,
            Salt = salt,
            IV = iv,
            TagSalt = tagSalt,
            Hash = Pbkdf2Hash.FromId(hashAlgorithmId),
            TagHash = Pbkdf2Hash.FromId(tagHashId),
            Bytes = data.Slice(0, index).ToArray(),
        };
    }

    public static AesEncryptionHeaderV1 CreateFromOptions(
        AesEncryptionProviderOptions options,
        int metadataSize = 0)
    {
        if (options is null)
            throw new ArgumentNullException(nameof(options));

        var saltSizeInBytes = options.SaltSize;
        using var rng = new Csrng();

        var header = new AesEncryptionHeaderV1()
        {
            Hash = options.Hash,
            TagHash = options.TagHash,
            MetaDataSize = metadataSize,
            TagSaltSize = options.TagSaltSize,
            SaltSize = options.SaltSize,
            Iterations = options.Iterations,
            Salt = rng.NextBytes(options.SaltSize),
            TagSalt = rng.NextBytes(options.TagSaltSize),
            IV = rng.NextBytes(16), // AES block size is 16 bytes
        };

        // header values
        // 1.  version  (short)
        // 2.  salt size (short)
        // 3.  key size (short)
        // 4.  pdk2 hash algorithm (short)
        // 5.  tag hash type (short)
        // 6.  tag salt size (short)
        // 7.  meta data size (int)
        // 8. iterations (int)
        // 9. salt (byte[])
        // 10. iv (byte[])
        // 11. tag salt (byte[])
        // 12. meta data (byte[])
        // 13. tag (byte[])
        // 13. encrypted data (byte[])
        var bytes = new byte[header.Size];

        int index = 0;

        BinaryPrimitives.WriteInt16LittleEndian(bytes.AsSpan(index), header.Version);
        index += sizeof(short);

        BinaryPrimitives.WriteInt16LittleEndian(bytes.AsSpan(index), header.SaltSize);
        index += sizeof(short);

        BinaryPrimitives.WriteInt16LittleEndian(bytes.AsSpan(index), (short)options.KeySize);
        index += sizeof(short);

        BinaryPrimitives.WriteInt16LittleEndian(bytes.AsSpan(index), header.Hash.Id);
        index += sizeof(short);

        BinaryPrimitives.WriteInt16LittleEndian(bytes.AsSpan(index), header.TagHash.Id);
        index += sizeof(short);

        BinaryPrimitives.WriteInt16LittleEndian(bytes.AsSpan(index), header.TagSaltSize);
        index += sizeof(short);

        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(index), header.MetaDataSize);
        index += sizeof(int);

        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(index), header.Iterations);
        index += sizeof(int);

        header.Salt.CopyTo(bytes.AsSpan(index));
        index += header.Salt.Length;

        header.IV.CopyTo(bytes.AsSpan(index));
        index += header.IV.Length;

        header.TagSalt.CopyTo(bytes.AsSpan(index));
        index += header.TagSalt.Length;

        header.Bytes = bytes;

        return header;
    }

    public void Dispose()
    {
        Array.Clear(this.Bytes, 0, this.Bytes.Length);
        Array.Clear(this.Salt, 0, this.Salt.Length);
        Array.Clear(this.TagSalt, 0, this.TagSalt.Length);
        Array.Clear(this.IV, 0, this.IV.Length);
    }
}