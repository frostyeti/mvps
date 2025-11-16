namespace FrostYeti.Collections.Generic;

public class StringMap : Map<string, string?>
{
    public StringMap()
        : base(StringComparer.OrdinalIgnoreCase)
    {
    }

    public StringMap(int capacity)
        : base(capacity, StringComparer.OrdinalIgnoreCase)
    {
    }

    public StringMap(IDictionary<string, string?> dictionary)
        : base(dictionary, StringComparer.OrdinalIgnoreCase)
    {
    }

    public StringMap(System.Collections.Specialized.NameValueCollection collection)
    {
        foreach (string key in collection.Keys)
        {
            if (key == null)
                continue;

            this.Add(key, collection[key]);
        }
    }

    public StringMap(IDictionary<string, string?> dictionary, IEqualityComparer<string> comparer)
        : base(dictionary, comparer)
    {
    }

    public StringMap(IEnumerable<(string, string?)> collection)
        : base(collection.ToDictionary(x => x.Item1, x => x.Item2), StringComparer.OrdinalIgnoreCase)
    {
    }

    public StringMap(IEnumerable<(string, string?)> collection, IEqualityComparer<string> comparer)
        : base(collection.ToDictionary(x => x.Item1, x => x.Item2), comparer)
    {
    }

    public StringMap(IEnumerable<KeyValuePair<string, string?>> collection)
        : base(collection, StringComparer.OrdinalIgnoreCase)
    {
    }

    public StringMap(IEnumerable<KeyValuePair<string, string?>> collection, IEqualityComparer<string> comparer)
        : base(collection, comparer)
    {
    }

    public StringMap(IEqualityComparer<string> comparer)
        : base(comparer)
    {
    }

    public StringMap(int capacity, IEqualityComparer<string> comparer)
        : base(capacity, comparer)
    {
    }
}