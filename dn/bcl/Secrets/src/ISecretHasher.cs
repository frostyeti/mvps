namespace FrostYeti.Secrets;

public interface ISecretHasher
{
    ReadOnlySpan<byte> ComputeHash(ReadOnlySpan<char> secret);

    ReadOnlySpan<byte> ComputeHash(ReadOnlySpan<byte> secret);
}