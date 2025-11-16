namespace FrostYeti.Collections.Generic;

public class OrderedStringMap : OrderedMap<string, string?>
{
    public OrderedStringMap()
        : base(StringComparer.OrdinalIgnoreCase)
    {
    }

    public OrderedStringMap(int capacity)
        : base(capacity, StringComparer.OrdinalIgnoreCase)
    {
    }

    public OrderedStringMap(IDictionary<string, string?> dictionary)
        : base(dictionary, StringComparer.OrdinalIgnoreCase)
    {
    }

    public OrderedStringMap(IDictionary<string, string?> dictionary, IEqualityComparer<string> comparer)
        : base(dictionary, comparer)
    {
    }

    public OrderedStringMap(IEnumerable<(string, string?)> collection)
        : base(collection.ToDictionary(x => x.Item1, x => x.Item2), StringComparer.OrdinalIgnoreCase)
    {
    }

    public OrderedStringMap(IEnumerable<(string, string?)> collection, IEqualityComparer<string> comparer)
        : base(collection.ToDictionary(x => x.Item1, x => x.Item2), comparer)
    {
    }

    public OrderedStringMap(IEnumerable<KeyValuePair<string, string?>> collection)
        : base(collection, StringComparer.OrdinalIgnoreCase)
    {
    }

    public OrderedStringMap(IEnumerable<KeyValuePair<string, string?>> collection, IEqualityComparer<string> comparer)
        : base(collection, comparer)
    {
    }

    public OrderedStringMap(IEqualityComparer<string> comparer)
        : base(comparer)
    {
    }

    public OrderedStringMap(int capacity, IEqualityComparer<string> comparer)
        : base(capacity, comparer)
    {
    }
}