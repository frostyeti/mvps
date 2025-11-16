using System.Text;

namespace FrostYeti.IO;

public class TeeTextWriter : TextWriter
{
    private readonly List<(TextWriter writer, bool leaveOpen)> writers;

    private bool disposed;

    public TeeTextWriter(bool leaveOpen, params TextWriter[] writers)
    {
        this.writers = new List<(TextWriter writer, bool leaveOpen)>();
        foreach (var writer in writers)
        {
            this.writers.Add((writer, leaveOpen));
        }
    }

    public TeeTextWriter(params TextWriter[] writers)
    {
        this.writers = writers?.Select(writer => (writer, false)).ToList() ?? throw new ArgumentNullException(nameof(writers));
    }

    public TeeTextWriter(IEnumerable<TeeTextWriter> writers, bool leaveOpen = false)
    {
        this.writers = new List<(TextWriter writer, bool leaveOpen)>();
        foreach (var writer in writers)
        {
            this.writers.Add((writer, leaveOpen));
        }
    }

    public TeeTextWriter(IEnumerable<(TextWriter writer, bool leaveOpen)> writers)
    {
        this.writers = writers?.ToList() ?? throw new ArgumentNullException(nameof(writers));
    }

    public override Encoding Encoding => this.writers.First().writer.Encoding;

    public override void Write(char value)
    {
        foreach (var (writer, _) in this.writers)
        {
            writer.Write(value);
        }
    }

    public override void WriteLine(string? value)
    {
        foreach (var (writer, _) in this.writers)
        {
            writer.WriteLine(value);
        }
    }

    public override async ValueTask DisposeAsync()
    {
        if (this.disposed)
        {
            return;
        }

        GC.SuppressFinalize(this);
        this.disposed = true;

        foreach (var (writer, leaveOpen) in this.writers)
        {
            if (!leaveOpen)
            {
                await writer.DisposeAsync().ConfigureAwait(false);
            }
        }

        await base.DisposeAsync().ConfigureAwait(false);
    }

    protected override void Dispose(bool disposing)
    {
        if (this.disposed)
        {
            return;
        }

        GC.SuppressFinalize(this);
        this.disposed = true;

        if (disposing)
        {
            foreach (var (writer, leaveOpen) in this.writers)
            {
                if (!leaveOpen)
                {
                    writer.Dispose();
                }
            }
        }

        base.Dispose(disposing);
    }
}