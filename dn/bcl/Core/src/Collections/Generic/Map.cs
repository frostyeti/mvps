namespace FrostYeti.Collections.Generic;

public class Map : Map<string, object?>
{
    public Map()
        : base(StringComparer.OrdinalIgnoreCase)
    {
    }

    public Map(int capacity)
        : base(capacity, StringComparer.OrdinalIgnoreCase)
    {
    }

    public Map(IDictionary<string, object?> dictionary)
        : base(dictionary, StringComparer.OrdinalIgnoreCase)
    {
    }

    public Map(IDictionary<string, object?> dictionary, IEqualityComparer<string> comparer)
        : base(dictionary, comparer)
    {
    }

    public Map(IEnumerable<(string, object?)> collection)
        : base(collection.ToDictionary(x => x.Item1, x => x.Item2), StringComparer.OrdinalIgnoreCase)
    {
    }

    public Map(IEnumerable<(string, object?)> collection, IEqualityComparer<string> comparer)
        : base(collection.ToDictionary(x => x.Item1, x => x.Item2), comparer)
    {
    }

    public Map(IEnumerable<KeyValuePair<string, object?>> collection)
        : base(collection, StringComparer.OrdinalIgnoreCase)
    {
    }

    public Map(IEnumerable<KeyValuePair<string, object?>> collection, IEqualityComparer<string> comparer)
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