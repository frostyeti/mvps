namespace FrostYeti.Lodi;

public struct ServiceLifetime
{
    public ServiceLifetime(string name)
    {
        this.Name = name.ToLower();
    }

    public ServiceLifetime()
    {
        this.Name = "Transient";
    }

    public static ServiceLifetime Transient { get; } = new("transient");

    public static ServiceLifetime Scoped { get; } = new("scoped");

    public static ServiceLifetime Singleton { get; } = new("singleton");

    public string Name { get; init; } = null!;

    public static implicit operator ServiceLifetime(string name)
    {
        return new ServiceLifetime(name);
    }

    public static implicit operator string(ServiceLifetime lifetime)
    {
        return lifetime.Name;
    }

    public static bool IsTransient(ServiceLifetime lifetime)
    {
        return lifetime.Name == Transient.Name;
    }

    public static bool IsScoped(ServiceLifetime lifetime)
    {
        return lifetime.Name == Scoped.Name;
    }

    public static bool IsSingleton(ServiceLifetime lifetime)
    {
        return lifetime.Name == Singleton.Name;
    }

    public override string ToString()
    {
        return this.Name;
    }
}