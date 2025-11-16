using FrostYeti.DotEnv.Documents;

namespace FrostYeti.DotEnv.Tokens;

public abstract class EnvScalarToken : EnvToken
{
    internal Capture Capture { get; set; } = Capture.None;
}