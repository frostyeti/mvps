namespace FrostYeti.Lodi;

public class LodiDependency
{

    public LodiDependency(Type type, ServiceLifetime lifetime, Func<LodiServiceProvider, object> factory)
    {
        this.ServiceType = type;
        this.Lifetime = lifetime;
        this.Factory = factory;
    }

    public LodiDependency(Type type, string name, ServiceLifetime lifetime, Func<LodiServiceProvider, object> factory)
    {
        this.ServiceType = type;
        this.Name = name;
        this.Lifetime = lifetime;
        this.Factory = factory;
    }

    public LodiDependency(Type type, ServiceLifetime lifetime, object instance)
    {
        this.ServiceType = type;
        this.Lifetime = lifetime;
        this.Service = instance;
        this.Factory = _ => instance;
    }

    public LodiDependency(Type type, string name, ServiceLifetime lifetime, object instance)
    {
        this.ServiceType = type;
        this.Name = name;
        this.Lifetime = lifetime;
        this.Service = instance;
        this.Factory = _ => instance;
    }

    public object? Service { get; internal set; } = null;

    public Func<LodiServiceProvider, object> Factory { get; internal set; } = null!;

    public Type ServiceType { get; init; } = null!;

    public string? Name { get; init; } = null;

    public ServiceLifetime Lifetime { get; init; }
}