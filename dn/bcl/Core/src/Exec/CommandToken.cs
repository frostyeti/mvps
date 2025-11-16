namespace FrostYeti.Exec;

public readonly struct CommandToken
{
    public CommandToken(string value, CommandTokenKind kind)
    {
        this.Value = value;
        this.Kind = kind;
    }

    public string Value { get; }

    public CommandTokenKind Kind { get; }

    public override string ToString() => this.Value;
}