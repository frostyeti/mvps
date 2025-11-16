namespace FrostYeti;

public class ResourceNotFoundException : Exception
{
    public ResourceNotFoundException()
        : base("The requested resource was not found.")
    {
    }

    public ResourceNotFoundException(string message)
        : base(message)
    {
    }

    public ResourceNotFoundException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    public ResourceNotFoundException(string resourceName, string resourceType)
        : base($"The resource '{resourceName}' of type '{resourceType}' was not found.")
    {
        this.ResourceName = resourceName;
        this.ResourceType = resourceType;
    }

    public string? ResourceName { get; }

    public string? ResourceType { get; }
}