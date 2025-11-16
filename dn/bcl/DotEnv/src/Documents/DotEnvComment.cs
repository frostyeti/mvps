using FrostYeti.DotEnv.Tokens;

namespace FrostYeti.DotEnv.Documents;

public class DotEnvComment : DotEnvNode
{
    public DotEnvComment(ReadOnlySpan<char> value, bool inline = false)
    {
        this.RawValue = value.ToArray();
        this.Inline = inline;
    }

    public DotEnvComment(char[] value, bool inline = false)
    {
        this.RawValue = value;
        this.Inline = inline;
    }

    public DotEnvComment(EnvCommentToken token)
    {
        this.RawValue = token.RawValue;
        this.Inline = token.Inline;
    }

    public bool Inline { get; set; } = false;
}