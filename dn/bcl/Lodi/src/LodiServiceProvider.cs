using System.Collections.Concurrent;

namespace FrostYeti.Lodi;

public class LodiServiceProvider : IServiceProvider, IDisposable
{
    private readonly ConcurrentBag<LodiDependency> dependencies = new();

    private readonly ConcurrentDictionary<Type, List<LodiDependency>> typeMap = new();

    private readonly ConcurrentDictionary<string, List<LodiDependency>> nameMap = new();

    private readonly ScopedLifetime scopedLifetime = new();

    private bool disposedValue;

    public LodiServiceProvider(LodiServiceProvider? parent = null)
    {
        if (parent is null)
        {
            this.IsRoot = true;
            this.RegisterSingleton(typeof(IServiceProviderLifetimeFactory), new LodiServiceProviderLifetimeFactory(this));
            return;
        }

        this.dependencies = parent.dependencies;
        this.typeMap = parent.typeMap;
        this.nameMap = parent.nameMap;
        this.IsRoot = false;

        var descriptor = this.dependencies.FirstOrDefault(o => o.ServiceType == typeof(IServiceProviderLifetimeFactory));
        if (descriptor is null)
        {
            this.RegisterSingleton(typeof(IServiceProviderLifetimeFactory), new LodiServiceProviderLifetimeFactory(this));
            return;
        }

        descriptor.Service = new LodiServiceProviderLifetimeFactory(this);
        descriptor.Factory = _ => descriptor.Service!;
    }

    protected bool IsRoot { get; }

    public LodiServiceProvider Register(LodiDependency dependency)
    {
        this.dependencies.Add(dependency);

        if (dependency.Name is not null)
        {
            if (!this.nameMap.TryGetValue(dependency.Name, out var list))
                list = new List<LodiDependency>();

            list.Add(dependency);
            this.nameMap[dependency.Name] = list;
        }
        else
        {
            if (!this.typeMap.TryGetValue(dependency.ServiceType, out var list))
                list = new List<LodiDependency>();

            list.Add(dependency);
            this.typeMap[dependency.ServiceType] = list;
        }

        return this;
    }

    public LodiServiceProvider RegisterTransient(Type type, Func<LodiServiceProvider, object> factory)
    {
        var dependency = new LodiDependency(type, ServiceLifetime.Transient, factory);
        this.Register(dependency);
        return this;
    }

    public LodiServiceProvider RegisterTransient<T>(Func<LodiServiceProvider, T> factory)
    {
        var dependency = new LodiDependency(typeof(T), ServiceLifetime.Transient, sp =>
        {
            var instance = factory(sp);
            if (instance is null)
                throw new InvalidOperationException($"Factory for type {typeof(T).FullName} returned null.");
            return instance;
        });
        this.Register(dependency);
        return this;
    }

    public LodiServiceProvider RegisterTransient<T>(string name, Func<LodiServiceProvider, T> factory)
    {
        var dependency = new LodiDependency(typeof(T), name, ServiceLifetime.Transient, sp =>
        {
            var instance = factory(sp);
            if (instance is null)
                throw new InvalidOperationException($"Factory for type {typeof(T).FullName} returned null.");
            return instance;
        });
        this.Register(dependency);
        return this;
    }

    public LodiServiceProvider RegisterTransient(Type type, string key, Func<LodiServiceProvider, object> factory)
    {
        var dependency = new LodiDependency(type, key, ServiceLifetime.Transient, factory);
        this.Register(dependency);
        return this;
    }

    public LodiServiceProvider RegisterScoped(Type type, Func<LodiServiceProvider, object> factory)
    {
        var dependency = new LodiDependency(type, ServiceLifetime.Scoped, factory);
        this.Register(dependency);
        return this;
    }

    public LodiServiceProvider RegisterScoped<T>(Func<LodiServiceProvider, T> factory)
    {
        var dependency = new LodiDependency(typeof(T), ServiceLifetime.Scoped, sp =>
        {
            var instance = factory(sp);
            if (instance is null)
                throw new InvalidOperationException($"Factory for type {typeof(T).FullName} returned null.");
            return instance;
        });
        this.Register(dependency);
        return this;
    }

    public LodiServiceProvider RegisterScoped<T>(string name, Func<LodiServiceProvider, T> factory)
    {
        var dependency = new LodiDependency(typeof(T), name, ServiceLifetime.Scoped, sp =>
        {
            var instance = factory(sp);
            if (instance is null)
                throw new InvalidOperationException($"Factory for type {typeof(T).FullName} returned null.");
            return instance;
        });
        this.Register(dependency);
        return this;
    }

    public LodiServiceProvider RegisterScoped(Type type, string key, Func<LodiServiceProvider, object> factory)
    {
        var dependency = new LodiDependency(type, key, ServiceLifetime.Scoped, factory);
        this.Register(dependency);
        return this;
    }

    public LodiServiceProvider RegisterSingleton(Type type, Func<LodiServiceProvider, object> factory)
    {
        var dependency = new LodiDependency(type, ServiceLifetime.Singleton, factory);
        this.Register(dependency);
        return this;
    }

    public LodiServiceProvider RegisterSingleton(Type type, string key, Func<LodiServiceProvider, object> factory)
    {
        var dependency = new LodiDependency(type, key, ServiceLifetime.Singleton, factory);
        this.Register(dependency);
        return this;
    }

    public LodiServiceProvider RegisterSingleton<T>(Func<LodiServiceProvider, T> factory)
    {
        var dependency = new LodiDependency(typeof(T), ServiceLifetime.Singleton, sp =>
        {
            var instance = factory(sp);
            if (instance is null)
                throw new InvalidOperationException($"Factory for type {typeof(T).FullName} returned null.");
            return instance;
        });
        this.Register(dependency);
        return this;
    }

    public LodiServiceProvider RegisterSingleton<T, TInstance>(Func<LodiServiceProvider, T> factory)
        where TInstance : T
    {
        var dependency = new LodiDependency(typeof(T), ServiceLifetime.Singleton, sp =>
        {
            var instance = factory(sp);
            if (instance is null)
                throw new InvalidOperationException($"Factory for type {typeof(T).FullName} returned null.");
            return instance;
        });
        this.Register(dependency);
        return this;
    }

    public LodiServiceProvider RegisterSingleton<T>(string key, Func<LodiServiceProvider, T> factory)
    {
        var dependency = new LodiDependency(typeof(T), key, ServiceLifetime.Singleton, sp =>
        {
            var instance = factory(sp);
            if (instance is null)
                throw new InvalidOperationException($"Factory for type {typeof(T).FullName} returned null.");
            return instance;
        });
        this.Register(dependency);
        return this;
    }

    public LodiServiceProvider RegisterSingleton(Type type, object instance)
    {
        var dependency = new LodiDependency(type, ServiceLifetime.Singleton, instance);
        this.Register(dependency);
        return this;
    }

    public LodiServiceProvider RegisterSingleton(Type type, string key, object instance)
    {
        var dependency = new LodiDependency(type, key, ServiceLifetime.Singleton, instance);
        this.Register(dependency);
        return this;
    }

    public LodiServiceProvider RegisterSingletonInstance<T>(T instance)
    {
        var dependency = new LodiDependency(typeof(T), ServiceLifetime.Singleton, instance!);
        this.Register(dependency);
        return this;
    }

    public LodiServiceProvider RegisterSingletonInstance<T>(string key, T instance)
    {
        var dependency = new LodiDependency(typeof(T), key, ServiceLifetime.Singleton, instance!);
        this.Register(dependency);
        return this;
    }

    public object? GetService(Type serviceType)
    {
        if (this.typeMap.TryGetValue(serviceType, out var list))
        {
            if (list.Count == 0)
                return null;

            var dependency = list[0];

            if (ServiceLifetime.IsSingleton(dependency.Lifetime))
            {
                if (dependency.Service is null)
                {
                    var instance = dependency.Factory(this);
                    dependency.Service = instance;

                    if (instance is null)
                    {
                        throw new InvalidOperationException($"Factory for type {dependency.ServiceType.FullName} returned null.");
                    }
                }
                else
                {
                }

                return dependency.Service;
            }
            else if (ServiceLifetime.IsScoped(dependency.Lifetime))
            {
                var instance = this.scopedLifetime.GetState(serviceType);
                if (instance is null)
                {
                    instance = dependency.Factory(this);
                    this.scopedLifetime.SetState(serviceType, dependency.Name, instance);
                }

                return instance;
            }
            else
            {
                return dependency.Factory(this);
            }
        }

        return null;
    }

    public object? GetService(string key)
    {
        if (this.nameMap.TryGetValue(key, out var list))
        {
            if (list.Count == 0)
                return null;

            var dependency = list[0];

            if (ServiceLifetime.IsSingleton(dependency.Lifetime))
            {
                if (dependency.Service is null)
                    dependency.Service = dependency.Factory(this);

                return dependency.Service;
            }
            else if (ServiceLifetime.IsScoped(dependency.Lifetime))
            {
                var instance = this.scopedLifetime.GetState(key);
                if (instance is null)
                {
                    instance = dependency.Factory(this);
                    this.scopedLifetime.SetState(dependency.ServiceType, key, instance);
                }

                return instance;
            }
            else
            {
                return dependency.Factory(this);
            }
        }

        return null;
    }

    public T? GetService<T>()
    {
        var service = this.GetService(typeof(T));
        if (service is null)
            return default;

        return (T)service;
    }

    public T? GetService<T>(string key)
    {
        var service = this.GetService(key);
        if (service is null)
            return default;

        return (T)service;
    }

    public T GetRequiredService<T>()
    {
        var service = this.GetService(typeof(T));
        if (service is null)
            throw new InvalidOperationException($"Service of type {typeof(T).FullName} is not registered.");

        return (T)service;
    }

    public T GetRequiredService<T>(string key)
    {
        var service = this.GetService(key);
        if (service is null)
            throw new InvalidOperationException($"Service with key '{key}' is not registered.");

        return (T)service;
    }

    public IServiceProvider CreateScope()
    {
        return new LodiServiceProvider(this);
    }

    public void Dispose()
    {
        if (this.disposedValue)
            return;

        this.disposedValue = true;

        foreach (var disposable in this.scopedLifetime.GetDisposables())
        {
            disposable.Dispose();
        }

        if (this.IsRoot)
        {
            foreach (var dependency in this.dependencies)
            {
                if (dependency.Service is IDisposable disposable)
                {
                    disposable.Dispose();
                    continue;
                }

                if (dependency.Service is IAsyncDisposable asyncDisposable)
                {
                    asyncDisposable.DisposeAsync();
                }
            }
        }

        this.scopedLifetime.Clear();
        this.typeMap.Clear();
        this.nameMap.Clear();
        this.dependencies.Clear();
    }
}

internal sealed class LodiServiceProviderLifetimeFactory : IServiceProviderLifetimeFactory
{
    private readonly LodiServiceProvider serviceProvider;

    public LodiServiceProviderLifetimeFactory(LodiServiceProvider serviceProvider)
        => this.serviceProvider = serviceProvider;

    public IServiceProviderLifetime CreateLifetime()
    {
        return new LodiScopedServiceLifetime(this.serviceProvider);
    }
}

// this is a private class, so fully implementing IDispose is overkill.
internal sealed class LodiScopedServiceLifetime : IServiceProviderLifetime
{
    private readonly LodiServiceProvider provider;

    public LodiScopedServiceLifetime(LodiServiceProvider provider)
    {
        this.provider = (LodiServiceProvider)provider.CreateScope();
    }

    public IServiceProvider ServiceProvider => this.provider;

    /// <summary>Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.</summary>
    public void Dispose()
    {
        this.provider.Dispose();
    }
}