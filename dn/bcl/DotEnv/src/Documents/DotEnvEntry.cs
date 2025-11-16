using FrostYeti.DotEnv.Tokens;

namespace FrostYeti.DotEnv.Documents;

public class DotEnvEntry : DotEnvNode
{
    private string? value;

    public DotEnvEntry(ReadOnlySpan<char> name, ReadOnlySpan<char> value)
    {
        this.Name = name.AsString();
        this.RawValue = value.ToArray();
    }

    public DotEnvEntry(string name, char[] value)
    {
        this.Name = name;
        this.RawValue = value.ToArray();
    }

    public DotEnvEntry(string name, EnvScalarToken token)
    {
        this.Name = name;
        this.RawValue = token.RawValue;
    }

    public DotEnvEntry(EnvNameToken name, EnvScalarToken token)
    {
        this.Name = name.Value;
        this.RawValue = token.RawValue;

        if (token is EnvStringToken stringToken)
            this.IsSecret = stringToken.IsSecret;
    }

    public string Name { get; }

    public bool IsSecret { get; set; } = false;

    public int Order { get; set; } = 0;

    public DotEnvQuote Quote { get; set; } = DotEnvQuote.Auto;

    public new string Value
    {
        get
        {
            if (this.IsSecret)
                return "********";

            return this.value ??= new string(this.RawValue);
        }
    }

    public void Deconstruct(out string name, out string value)
    {
        name = this.Name;
        value = this.GetRawValueAsString();
    }

    public string GetRawValueAsString()
    {
        if (this.value is null)
            this.value = new string(this.RawValue);

        return this.value;
    }

    public void SetRawValue(char[] value)
    {
        this.value = null; // Reset cached value
        this.RawValue = value;
    }

    public void SetRawValue(ReadOnlySpan<char> value)
    {
        this.value = null; // Reset cached value
        this.RawValue = value.ToArray();
    }

    public void SetRawValue(EnvScalarToken token)
    {
        this.value = null; // Reset cached value
        this.RawValue = token.RawValue;
    }

    public override string ToString()
    {
        return $"{this.Name}=`{this.Value}`";
    }
}