namespace FrostYeti.Collections.Generic;

public class Inputs : Dictionary<string, object?>
{
    public Inputs()
     : base(StringComparer.OrdinalIgnoreCase)
    {
    }

    public Inputs(int capacity)
        : base(capacity, StringComparer.OrdinalIgnoreCase)
    {
    }

    public Inputs(IDictionary<string, object?> dictionary)
        : base(dictionary, StringComparer.OrdinalIgnoreCase)
    {
    }

    public Inputs(IDictionary<string, object?> dictionary, IEqualityComparer<string> comparer)
        : base(dictionary, comparer)
    {
    }

    public Inputs(IEnumerable<(string, object?)> collection)
        : base(collection.ToDictionary(x => x.Item1, x => x.Item2), StringComparer.OrdinalIgnoreCase)
    {
    }

    public Inputs(IEnumerable<(string, object?)> collection, IEqualityComparer<string> comparer)
        : base(collection.ToDictionary(x => x.Item1, x => x.Item2), comparer)
    {
    }

    public Inputs(IEnumerable<KeyValuePair<string, object?>> collection)
        : base(collection, StringComparer.OrdinalIgnoreCase)
    {
    }

    public Inputs(IEnumerable<KeyValuePair<string, object?>> collection, IEqualityComparer<string> comparer)
        : base(collection, comparer)
    {
    }

    public Inputs(IEqualityComparer<string> comparer)
        : base(comparer)
    {
    }

    public Inputs(int capacity, IEqualityComparer<string> comparer)
        : base(capacity, comparer)
    {
    }

    public static Inputs Empty => new EmptyInputs();

    public virtual bool IsEmpty => this.Count == 0;

    public virtual bool IsReadOnly => false;
}

public class EmptyInputs : Inputs
{
    public EmptyInputs()
        : base(StringComparer.OrdinalIgnoreCase)
    {
    }

    public override bool IsEmpty => true;

    public override bool IsReadOnly => true;

    public new void Add(string key, object? value)
    {
        throw new InvalidOperationException("Cannot add to Empty Inputs.");
    }

    public override string ToString() => "Empty Inputs";
}