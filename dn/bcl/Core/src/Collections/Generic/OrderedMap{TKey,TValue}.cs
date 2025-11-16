namespace FrostYeti.Collections.Generic;

public class OrderedMap<TKey, TValue> : OrderedDictionary<TKey, TValue>
    where TKey : notnull
{
    public OrderedMap()
        : base()
    {
    }

    public OrderedMap(int capacity)
        : base(capacity)
    {
    }

    public OrderedMap(IDictionary<TKey, TValue> dictionary)
        : base(dictionary)
    {
    }

    public OrderedMap(IDictionary<TKey, TValue> dictionary, IEqualityComparer<TKey> comparer)
        : base(dictionary, comparer)
    {
    }

    public OrderedMap(IEnumerable<(TKey, TValue)> collection)
    {
        foreach (var item in collection)
        {
            this.Add(item.Item1, item.Item2);
        }
    }

    public OrderedMap(IEnumerable<KeyValuePair<TKey, TValue>> collection)
        : base(collection)
    {
    }

    public OrderedMap(IEnumerable<KeyValuePair<TKey, TValue>> collection, IEqualityComparer<TKey> comparer)
        : base(collection, comparer)
    {
    }

    public OrderedMap(IEqualityComparer<TKey> comparer)
        : base(comparer)
    {
    }

    public OrderedMap(int capacity, IEqualityComparer<TKey> comparer)
        : base(capacity, comparer)
    {
    }

    public OrderedMap<TKey, TValue> Add((TKey, TValue) item)
    {
        this.Add(item.Item1, item.Item2);
        return this;
    }

    public OrderedMap<TKey, TValue> AddRange(IEnumerable<(TKey, TValue)> items)
    {
        foreach (var item in items)
        {
            this.Add(item);
        }

        return this;
    }
}