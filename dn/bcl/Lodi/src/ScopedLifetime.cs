using System.Collections.Concurrent;

namespace FrostYeti.Lodi;

public class ScopedLifetime
{
    private readonly ConcurrentDictionary<Type, List<object?>> typedState = new();

    private readonly ConcurrentDictionary<string, List<object?>> namedInstances = new();

    public bool ContainsKey(Type type)
    {
        return this.typedState.ContainsKey(type);
    }

    public bool ContainsKey(string name)
    {
        return this.namedInstances.ContainsKey(name);
    }

    public void SetState(Type type, string? key, object instance)
    {
        if (!this.typedState.TryGetValue(type, out var set))
            set = new List<object?>();

        set.Add(instance);
        this.typedState[type] = set;

        if (key is not null && key.Length > 0)
        {
            if (!this.namedInstances.TryGetValue(key, out var namedSet))
                namedSet = new List<object?>();

            namedSet.Add(instance);
            this.namedInstances[key] = namedSet;
        }
    }

    public object? GetState(Type type)
    {
        this.typedState.TryGetValue(type, out var set);
        var instance = set?.Count > 0 ? set[0] : null;
        return instance;
    }

    public object? GetState(string name)
    {
        this.namedInstances.TryGetValue(name, out var set);
        var instance = set?.Count > 0 ? set[0] : null;
        return instance;
    }

    public IEnumerable<object?> GetAllStates(Type type)
    {
        this.typedState.TryGetValue(type, out var set);
        return set ?? Enumerable.Empty<object?>();
    }

    public IEnumerable<object?> GetAllStates(string name)
    {
        this.namedInstances.TryGetValue(name, out var set);
        return set ?? Enumerable.Empty<object?>();
    }

    public void Clear()
    {
        this.typedState.Clear();
    }

    public IEnumerable<IDisposable> GetDisposables()
    {
        var list = new List<IDisposable>();
        foreach (var kv in this.typedState)
        {
            if (kv.Value is IDisposable disposable)
                list.Add(disposable);
        }

        foreach (var kv in this.namedInstances)
        {
            if (kv.Value is IDisposable disposable)
            {
                if (!list.Contains(disposable))
                    list.Add(disposable);
            }
        }

        return list;
    }
}