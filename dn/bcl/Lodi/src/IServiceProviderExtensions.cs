using FrostYeti.Lodi;

namespace FrostYeti;

public static class IServiceProviderExtensions
{
    public static object? LodiGetService(this IServiceProvider provider, string key)
    {
        if (provider is LodiServiceProvider lodiProvider)
        {
            return lodiProvider.GetService(key);
        }

        return null;
    }

    public static T? LodiGetService<T>(this IServiceProvider provider)
        where T : notnull
    {
        if (provider is LodiServiceProvider lodiProvider)
        {
            return (T?)lodiProvider.GetService(typeof(T));
        }

        return (T?)provider.GetService(typeof(T));
    }

    public static T? LodiGetService<T>(this IServiceProvider provider, string key)
        where T : notnull
    {
        if (provider is LodiServiceProvider lodiProvider)
        {
            return lodiProvider.GetService<T>(key);
        }

        return default;
    }

    public static T LodiGetRequiredService<T>(this IServiceProvider provider)
        where T : notnull
    {
        if (provider is LodiServiceProvider lodiProvider)
        {
            return lodiProvider.GetRequiredService<T>();
        }

        var service = (T?)provider.GetService(typeof(T));
        if (service == null)
        {
            throw new InvalidOperationException($"Service of type {typeof(T)} is not registered.");
        }

        return service;
    }

    public static T LodiGetRequiredService<T>(this IServiceProvider provider, string key)
        where T : notnull
    {
        if (provider is LodiServiceProvider lodiProvider)
        {
            return lodiProvider.GetRequiredService<T>(key);
        }

        throw new InvalidOperationException("The service provider is not a LodiServiceProvider.");
    }
}