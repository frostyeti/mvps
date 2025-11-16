namespace FrostYeti.Collections.Generic;

public class OrderedMap<TValue> : OrderedMap<string, TValue>
{
    public OrderedMap()
        : base(StringComparer.OrdinalIgnoreCase)
    {
    }

    public OrderedMap(int capacity)
        : base(capacity, StringComparer.OrdinalIgnoreCase)
    {
    }

    public OrderedMap(IDictionary<string, TValue> dictionary)
        : base(dictionary, StringComparer.OrdinalIgnoreCase)
    {
    }

    public OrderedMap(IDictionary<string, TValue> dictionary, IEqualityComparer<string> comparer)
        : base(dictionary, comparer)
    {
    }

    public OrderedMap(IEnumerable<(string, TValue)> collection)
        : base(collection.ToDictionary(x => x.Item1, x => x.Item2), StringComparer.OrdinalIgnoreCase)
    {
    }

    public OrderedMap(IEnumerable<(string, TValue)> collection, IEqualityComparer<string> comparer)
        : base(collection.ToDictionary(x => x.Item1, x => x.Item2), comparer)
    {
    }

    public OrderedMap(IEnumerable<KeyValuePair<string, TValue>> collection)
        : base(collection, StringComparer.OrdinalIgnoreCase)
    {
    }

    public OrderedMap(IEnumerable<KeyValuePair<string, TValue>> collection, IEqualityComparer<string> comparer)
        : base(collection, comparer)
    {
    }

    public OrderedMap(IEqualityComparer<string> comparer)
        : base(comparer)
    {
    }

    public OrderedMap(int capacity, IEqualityComparer<string> comparer)
        : base(capacity, comparer)
    {
    }
}