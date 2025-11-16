using System.ComponentModel;
using System.Security.Cryptography;

namespace FrostYeti.Crypto;

// Pbkdf2
public readonly struct Pbkdf2Hash
{

    public Pbkdf2Hash(HashAlgorithmName name)
    {
        switch (name.Name)
        {
            case "SHA1":
                this.Id = 1;
                this.Name = "SHA1";
                this.Size = 20; // SHA1 produces a 20-byte hash
                break;
            case "SHA256":
                this.Id = 2;
                this.Name = "SHA256";
                this.Size = 32; // SHA256 produces a 32-byte hash
                break;
            case "SHA384":
                this.Id = 3;
                this.Name = "SHA384";
                this.Size = 48; // SHA384 produces a 48-byte hash
                break;
            case "SHA3-256":
                this.Id = 5;
                this.Name = "SHA3-256";
                this.Size = 32; // SHA3-256 produces a 32-byte hash
                break;

            case "SHA3-384":
                this.Id = 6;
                this.Name = "SHA3-384";
                this.Size = 48; // SHA3-384 produces a 48-byte hash
                break;
            case "SHA3-512":
                this.Id = 7;
                this.Name = "SHA3-512";
                this.Size = 64; // SHA3-512 produces a 64-byte hash
                break;
            case "SHA512":
                this.Id = 4;
                this.Name = "SHA512";
                this.Size = 64; // SHA512 produces a 64-byte hash
                break;
            default:
                throw new ArgumentException("Unsupported hash algorithm", nameof(name));
        }
    }

    public static Pbkdf2Hash SHA1 => new(HashAlgorithmName.SHA1);

    public static Pbkdf2Hash SHA256 => new(HashAlgorithmName.SHA256);

    public static Pbkdf2Hash SHA384 => new(HashAlgorithmName.SHA384);

    public static Pbkdf2Hash SHA512 => new(HashAlgorithmName.SHA512);

    public static Pbkdf2Hash SHA3_256 => new(HashAlgorithmName.SHA3_256);

    public static Pbkdf2Hash SHA3_384 => new(HashAlgorithmName.SHA3_384);

    public static Pbkdf2Hash SHA3_512 => new(HashAlgorithmName.SHA3_512);

    public short Id { get; init; }

    public string Name { get; init; } = string.Empty;

    public int Size { get; init; } = 0;

    public static Pbkdf2Hash FromName(string name)
    {
        return name switch
        {
            "SHA1" => SHA1,
            "SHA256" => SHA256,
            "SHA384" => SHA384,
            "SHA512" => SHA512,
            "SHA3-256" => SHA3_256,
            "SHA3-384" => SHA3_384,
            "SHA3-512" => SHA3_512,
            _ => throw new InvalidEnumArgumentException(nameof(name), -1, typeof(string)),
        };
    }

    public static Pbkdf2Hash FromId(short id)
    {
        return id switch
        {
            1 => SHA1,
            2 => SHA256,
            3 => SHA384,
            4 => SHA512,
            5 => SHA3_256,
            6 => SHA3_384,
            7 => SHA3_512,
            _ => throw new InvalidEnumArgumentException(nameof(id), id, typeof(short)),
        };
    }

    public HMAC CreateHmac(byte[] key)
    {
        return this.Id switch
        {
            1 => new HMACSHA1(key),
            2 => new HMACSHA256(key),
            3 => new HMACSHA384(key),
            4 => new HMACSHA512(key),
            5 => new HMACSHA3_256(key),
            6 => new HMACSHA3_384(key),
            7 => new HMACSHA3_512(key),
            _ => throw new InvalidEnumArgumentException(nameof(this.Id), this.Id, typeof(short)),
        };
    }

    public static implicit operator HashAlgorithmName(Pbkdf2Hash hash)
    {
        switch (hash.Id)
        {
            case 1: return HashAlgorithmName.SHA1;
            case 2: return HashAlgorithmName.SHA256;
            case 3: return HashAlgorithmName.SHA384;
            case 4: return HashAlgorithmName.SHA512;
            case 5: return HashAlgorithmName.SHA3_256;
            case 6: return HashAlgorithmName.SHA3_384;
            case 7: return HashAlgorithmName.SHA3_512;
            default:
                return new HashAlgorithmName(hash.Name);
        }
    }

    public static implicit operator Pbkdf2Hash(HashAlgorithmName name)
    {
        return new Pbkdf2Hash(name);
    }

    public override string ToString()
    {
        return this.Name;
    }
}