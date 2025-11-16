namespace FrostYeti.Exec;

public class ProcessException : SystemException
{
    public ProcessException()
    {
    }

    public ProcessException(int exitCode)
        : base($"Process exited with code {exitCode}")
    {
    }

    public ProcessException(int exitCode, string processName, string? message = null, Exception? inner = null)
        : base(message ?? $"Process {processName} exited with code {exitCode}", inner)
    {
    }

    public ProcessException(string? message)
        : base(message)
    {
    }

    public ProcessException(string? message, System.Exception? inner)
        : base(message, inner)
    {
    }
}