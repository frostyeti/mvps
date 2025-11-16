namespace FrostYeti.DotEnv;

public class DotEnvSerializerOptions
{
    public bool Backticks { get; set; } = true;

    public bool Json { get; set; }

    public bool Yaml { get; set; }

    public bool SubExpressions { get; set; } = false;

    /// <summary>
    /// Gets or sets a value indicating whether the quoted command substitution is enabled.
    /// When enabled command substitution expresions in in double quotes are handled propertly, e.g. Test="Value is $(command)".
    /// And the more complex case of nested quotes: TEST="Value is $(echo "world")".
    /// </summary>
    public bool QuotedCommandSubstitution { get; set; } = false;

    public virtual object Clone()
    {
        var copy = new DotEnvSerializerOptions()
        {
            Backticks = this.Backticks,
            Json = this.Json,
            Yaml = this.Yaml,
            QuotedCommandSubstitution = this.QuotedCommandSubstitution,
        };

        return copy;
    }
}