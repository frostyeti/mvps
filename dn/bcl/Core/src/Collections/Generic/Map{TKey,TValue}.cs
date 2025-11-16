namespace FrostYeti.Collections.Generic;

public class Map<TKey, TValue> : Dictionary<TKey, TValue>
    where TKey : notnull
{
    public Map()
        : base()
    {
    }

    public Map(int capacity)
        : base(capacity)
    {
    }

    public Map(IDictionary<TKey, TValue> dictionary)
        : base(dictionary)
    {
    }

    public Map(IDictionary<TKey, TValue> dictionary, IEqualityComparer<TKey> comparer)
        : base(dictionary, comparer)
    {
    }

    public Map(IEnumerable<(TKey, TValue)> collection)
        : base(collection.ToDictionary(x => x.Item1, x => x.Item2))
    {
    }

    public Map(IEnumerable<KeyValuePair<TKey, TValue>> collection)
        : base(collection)
    {
    }

    public Map(IEnumerable<KeyValuePair<TKey, TValue>> collection, IEqualityComparer<TKey> comparer)
        : base(collection, comparer)
    {
    }

    public Map(IEqualityComparer<TKey> comparer)
        : base(comparer)
    {
    }

    public Map(int capacity, IEqualityComparer<TKey> comparer)
        : base(capacity, comparer)
    {
    }

    public Map<TKey, TValue> Add((TKey, TValue) item)
    {
        this.Add(item.Item1, item.Item2);
        return this;
    }

    public Map<TKey, TValue> AddRange(IEnumerable<(TKey, TValue)> items)
    {
        foreach (var (key, value) in items)
        {
            this.Add(key, value);
        }

        return this;
    }
}