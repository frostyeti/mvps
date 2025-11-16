namespace FrostYeti.Collections.Generic;

public class Outputs : Dictionary<string, object?>
{
    public Outputs()
        : base(StringComparer.OrdinalIgnoreCase)
    {
    }

    public Outputs(int capacity)
        : base(capacity, StringComparer.OrdinalIgnoreCase)
    {
    }

    public Outputs(IDictionary<string, object?> dictionary)
        : base(dictionary, StringComparer.OrdinalIgnoreCase)
    {
    }

    public Outputs(IDictionary<string, object?> dictionary, IEqualityComparer<string> comparer)
        : base(dictionary, comparer)
    {
    }

    public Outputs(IEnumerable<(string, object?)> collection)
        : base(collection.ToDictionary(x => x.Item1, x => x.Item2), StringComparer.OrdinalIgnoreCase)
    {
    }

    public Outputs(IEnumerable<(string, object?)> collection, IEqualityComparer<string> comparer)
        : base(collection.ToDictionary(x => x.Item1, x => x.Item2), comparer)
    {
    }

    public Outputs(IEnumerable<KeyValuePair<string, object?>> collection)
        : base(collection, StringComparer.OrdinalIgnoreCase)
    {
    }

    public Outputs(IEnumerable<KeyValuePair<string, object?>> collection, IEqualityComparer<string> comparer)
        : base(collection, comparer)
    {
    }

    public Outputs(IEqualityComparer<string> comparer)
        : base(comparer)
    {
    }

    public Outputs(int capacity, IEqualityComparer<string> comparer)
        : base(capacity, comparer)
    {
    }

    public static Outputs Empty => new EmptyOutputs();

    public virtual bool IsEmpty => this.Count == 0;

    public virtual bool IsReadOnly => false;
}

public class EmptyOutputs : Outputs
{
    public EmptyOutputs()
        : base(0)
    {
    }

    public override bool IsEmpty => true;

    public override bool IsReadOnly => true;

    public new void Add(string key, object? value)
    {
        throw new NotSupportedException("Cannot add items to an empty Outputs instance.");
    }
}