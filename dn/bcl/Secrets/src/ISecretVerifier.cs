namespace FrostYeti;

public interface ISecretVerifier
{
    bool Verify(ReadOnlySpan<char> secret, ReadOnlySpan<char> hash);

    bool Verify(ReadOnlySpan<byte> secret, ReadOnlySpan<byte> hash);
}