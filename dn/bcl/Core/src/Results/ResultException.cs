using System.Diagnostics;

namespace FrostYeti.Results;

public class ResultException : System.Exception
{
    public ResultException()
    {
    }

    public ResultException(string? message)
        : base(message)
    {
    }

    public ResultException(string? message, System.Exception? inner)
        : base(message, inner)
    {
    }

    public ResultException(System.Exception ex)
        : base($"Result error: {ex.Message}", ex)
    {
    }

    public virtual string Target { get; protected set; } = string.Empty;

    public virtual int LineNumber { get; protected set; }

    public virtual string FilePath { get; protected set; } = string.Empty;

    public static ResultException FromUnknown(object? error, string? message = null)
    {
        message ??= "Unknown error: ";
        if (error is Exception e)
            return new ResultException(e);

        if (error is System.Exception ex)
            return new ResultException(ex);

        if (error != null)
            return new ResultException($"{message} {error}");

        return new ResultException(message);
    }

    public static ResultException FromError(Exception error)
    {
        return new ResultException(error);
    }

    public static ResultException FromException(System.Exception ex)
    {
        return new ResultException(ex);
    }

    public ResultException TrackCallerInfo(
        [System.Runtime.CompilerServices.CallerLineNumber] int line = 0,
        [System.Runtime.CompilerServices.CallerFilePath] string file = "",
        [System.Runtime.CompilerServices.CallerMemberName] string target = "")
    {
        this.Target = target;
        this.LineNumber = line;
        this.FilePath = file;
        return this;
    }
}