using System.Text;

using FrostYeti.Extras;

namespace FrostYeti.Exec;

public readonly struct Output
{
    public Output()
    {
        this.ExitCode = 0;
        this.FileName = string.Empty;
        this.Stdout = [];
        this.Stderr = [];
        this.StartTime = DateTime.MinValue;
        this.ExitTime = DateTime.MinValue;
    }

    public Output(
        string fileName,
        int exitCode,
        Exception error,
        byte[]? stdout = null,
        byte[]? stderr = null,
        DateTime? startTime = null,
        DateTime? exitTime = null)
    {
        this.FileName = fileName;
        this.ExitCode = exitCode;
        this.Error = error;
        this.Stdout = stdout ?? [];
        this.Stderr = stderr ?? [];
        this.StartTime = startTime ?? DateTime.MinValue;
        this.ExitTime = exitTime ?? DateTime.MinValue;
    }

    public Output(
        string fileName,
        int exitCode,
        byte[]? stdout = null,
        byte[]? stderr = null,
        DateTime? startTime = null,
        DateTime? exitTime = null)
    {
        this.FileName = fileName;
        this.ExitCode = exitCode;
        this.Stdout = stdout ?? [];
        this.Stderr = stderr ?? [];
        this.StartTime = startTime ?? DateTime.MinValue;
        this.ExitTime = exitTime ?? DateTime.MinValue;
    }

    public int ExitCode { get; }

    public string FileName { get; }

    public byte[] Stdout { get; }

    public byte[] Stderr { get; }

    public DateTime StartTime { get; }

    public DateTime ExitTime { get; }

    public Exception? Error { get; init; }

    public bool IsOk => this.ExitCode == 0 && this.Error is null;

    public bool IsError => this.ExitCode != 0 || this.Error is not null;

    public Output ThrowOnBadExit()
    {
        if (this.ExitCode != 0)
        {
            throw new ProcessException(
                this.ExitCode,
                this.FileName,
                $"Process '{this.FileName}' failed with exit code {this.ExitCode}.",
                this.Error);
        }

        if (this.Error is not null)
        {
            throw new ProcessException(
                this.ExitCode,
                this.FileName,
                $"Process '{this.FileName}' failed with error: {this.Error.Message}",
                this.Error);
        }

        return this;
    }

    public Output ThrowOnBadExit(Func<int, Exception?, bool> isValid)
    {
        if (isValid(this.ExitCode, this.Error))
        {
            return this;
        }

        throw new ProcessException(
            this.ExitCode,
            this.FileName,
            $"Process '{this.FileName}' failed with exit code {this.ExitCode}.",
            this.Error);
    }

    public string Text(Encoding? encoding = null)
    {
        encoding ??= System.Text.Encoding.UTF8NoBom;

        return this.Stdout.Length > 0
            ? encoding.GetString(this.Stdout)
            : string.Empty;
    }

    public string ErrorText(Encoding? encoding = null)
    {
        encoding ??= System.Text.Encoding.UTF8NoBom;

        return this.Stderr.Length > 0
            ? encoding.GetString(this.Stderr)
            : string.Empty;
    }

    public IEnumerable<string> Lines(Encoding? encoding = null)
    {
        // read lines as from a stream or stream reader from the stdout byte array
        encoding ??= System.Text.Encoding.UTF8NoBom;
        using var stream = new MemoryStream(this.Stdout);
        using var reader = new StreamReader(stream, encoding);
        string? line;
        while ((line = reader.ReadLine()) is not null)
        {
            yield return line;
        }

        yield break;
    }

    public IEnumerable<string> ErrorLines(Encoding? encoding = null)
    {
        // read lines as from a stream or stream reader from the stderr byte array
        encoding ??= System.Text.Encoding.UTF8NoBom;
        using var stream = new MemoryStream(this.Stderr);
        using var reader = new StreamReader(stream, encoding);
        string? line;
        while ((line = reader.ReadLine()) is not null)
        {
            yield return line;
        }

        yield break;
    }
}