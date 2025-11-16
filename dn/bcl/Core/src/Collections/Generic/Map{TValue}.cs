namespace FrostYeti.Collections.Generic;

public class Map<TValue> : Map<string, TValue>
{
    public Map()
        : base(StringComparer.OrdinalIgnoreCase)
    {
    }

    public Map(int capacity)
        : base(capacity, StringComparer.OrdinalIgnoreCase)
    {
    }

    public Map(IDictionary<string, TValue> dictionary)
        : base(dictionary, StringComparer.OrdinalIgnoreCase)
    {
    }

    public Map(IDictionary<string, TValue> dictionary, IEqualityComparer<string> comparer)
        : base(dictionary, comparer)
    {
    }

    public Map(IEnumerable<(string, TValue)> collection)
        : base(collection.ToDictionary(x => x.Item1, x => x.Item2), StringComparer.OrdinalIgnoreCase)
    {
    }

    public Map(IEnumerable<(string, TValue)> collection, IEqualityComparer<string> comparer)
        : base(collection.ToDictionary(x => x.Item1, x => x.Item2), comparer)
    {
    }

    public Map(IEnumerable<KeyValuePair<string, TValue>> collection)
        : base(collection, StringComparer.OrdinalIgnoreCase)
    {
    }

    public Map(IEnumerable<KeyValuePair<string, TValue>> collection, IEqualityComparer<string> comparer)
        : base(collection, comparer)
    {
    }

    public Map(IEqualityComparer<string> comparer)
        : base(comparer)
    {
    }

    public Map(int capacity, IEqualityComparer<string> comparer)
        : base(capacity, comparer)
    {
    }
}