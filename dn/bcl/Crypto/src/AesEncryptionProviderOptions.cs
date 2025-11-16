using System.Security.Cryptography;
using System.Text;

namespace FrostYeti.Crypto;

public class AesEncryptionProviderOptions
{
    public int Iterations { get; set; } = 60000;

    public short SaltSize { get; set; } = 8;

    public short TagSaltSize { get; set; } = 8;

    public Pbkdf2Hash Hash { get; set; } = Pbkdf2Hash.SHA256;

    public Pbkdf2Hash TagHash { get; set; } = Pbkdf2Hash.SHA256;

    public short KeySize { get; set; } = 32; // 256 bits

    public byte[] Key { get; set; } = [];

    public AesEncryptionProviderOptions WithKey(ReadOnlySpan<byte> key)
    {
        if (key.IsEmpty)
            throw new ArgumentException("Key cannot be empty.", nameof(key));

        this.Key = key.ToArray();
        return this;
    }

    public AesEncryptionProviderOptions WithKey(ReadOnlySpan<char> key, System.Text.Encoding? encoding = null)
    {
        encoding ??= EncryptionUtil.DefaultEncoding;
        if (key.IsEmpty)
            throw new ArgumentException("Key cannot be empty.", nameof(key));

        var keyValue = key.ToArray();

        this.Key = encoding.GetBytes(keyValue);
        Array.Clear(keyValue, 0, keyValue.Length);
        return this;
    }

    public AesEncryptionProviderOptions WithIterations(int iterations)
    {
        if (iterations <= 0)
            throw new ArgumentOutOfRangeException(nameof(iterations), "Iterations must be greater than zero.");

        this.Iterations = iterations;
        return this;
    }

    public AesEncryptionProviderOptions Use128()
    {
        this.KeySize = 16; // 128 bits
        return this;
    }

    public AesEncryptionProviderOptions Use192()
    {
        this.KeySize = 24; // 192 bits
        return this;
    }

    public AesEncryptionProviderOptions Use256()
    {
        this.KeySize = 32; // 256 bits
        return this;
    }
}