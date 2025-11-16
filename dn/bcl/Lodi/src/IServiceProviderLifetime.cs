namespace FrostYeti.Lodi;

public interface IServiceProviderLifetime : IDisposable
{
    IServiceProvider ServiceProvider { get; }
}