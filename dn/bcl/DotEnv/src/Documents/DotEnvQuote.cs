namespace FrostYeti.DotEnv.Documents;

public enum DotEnvQuote
{
    None = 0,
    Single = 1,
    Double = 2,
    Backtick = 3,
    Auto = 4, // Automatically determine the quote type based on the value content
    Json = 5, // Use JSON-style quoting
    Yaml = 6, // Use YAML-style quoting
}