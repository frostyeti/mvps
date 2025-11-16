namespace FrostYeti.Collections.Generic;

public class OrderedMap : OrderedMap<string, object?>
{
    public OrderedMap()
        : base(StringComparer.OrdinalIgnoreCase)
    {
    }

    public OrderedMap(int capacity)
        : base(capacity, StringComparer.OrdinalIgnoreCase)
    {
    }

    public OrderedMap(int capacity, IEqualityComparer<string> comparer)
        : base(capacity, comparer)
    {
    }

    public OrderedMap(IDictionary<string, object?> dictionary)
        : base(dictionary, StringComparer.OrdinalIgnoreCase)
    {
    }

    public OrderedMap(IDictionary<string, object?> dictionary, IEqualityComparer<string> comparer)
        : base(dictionary, comparer)
    {
    }

    public OrderedMap(IEnumerable<KeyValuePair<string, object?>> collection)
        : base(collection, StringComparer.OrdinalIgnoreCase)
    {
    }

    public OrderedMap(IEnumerable<KeyValuePair<string, object?>> collection, IEqualityComparer<string> comparer)
        : base(collection, comparer)
    {
    }

    public OrderedMap(IEnumerable<(string, object?)> collection)
        : base(collection.ToDictionary(x => x.Item1, x => x.Item2), StringComparer.OrdinalIgnoreCase)
    {
    }

    public OrderedMap(IEnumerable<(string, object?)> collection, IEqualityComparer<string> comparer)
        : base(collection.ToDictionary(x => x.Item1, x => x.Item2), comparer)
    {
    }
}