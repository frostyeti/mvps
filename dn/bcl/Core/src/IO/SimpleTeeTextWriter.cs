using System.Text;

namespace FrostYeti.IO;

public class SimpleTeeTextWriter : TextWriter
{
    private readonly TextWriter writer1;

    private readonly TextWriter writer2;

    private readonly bool leaveWriterOpen1;

    private readonly bool leaveWriterOpen2;

    private bool disposed;

    public SimpleTeeTextWriter(TextWriter writer1, TextWriter writer2, bool leaveWriterOpen1 = false, bool leaveWriterOpen2 = false)
    {
        this.writer1 = writer1 ?? throw new ArgumentNullException(nameof(writer1));
        this.writer2 = writer2 ?? throw new ArgumentNullException(nameof(writer2));
        this.leaveWriterOpen1 = leaveWriterOpen1;
        this.leaveWriterOpen2 = leaveWriterOpen2;
    }

    public override Encoding Encoding => this.writer1.Encoding;

    public override void Write(char value)
    {
        this.writer1.Write(value);
        this.writer2.Write(value);
    }

    public override void WriteLine(string? value)
    {
        this.writer1.WriteLine(value);
        this.writer2.WriteLine(value);
    }

    public override async ValueTask DisposeAsync()
    {
        if (this.disposed)
        {
            return;
        }

        GC.SuppressFinalize(this);
        this.disposed = true;

        if (!this.leaveWriterOpen1)
        {
            await this.writer1.DisposeAsync().ConfigureAwait(false);
        }

        if (!this.leaveWriterOpen2)
        {
            await this.writer2.DisposeAsync().ConfigureAwait(false);
        }

        await base.DisposeAsync().ConfigureAwait(false);
    }

    protected override void Dispose(bool disposing)
    {
        if (this.disposed)
        {
            return;
        }

        this.disposed = true;

        if (disposing)
        {
            if (!this.leaveWriterOpen1)
            {
                this.writer1.Dispose();
            }

            if (!this.leaveWriterOpen2)
            {
                this.writer2.Dispose();
            }
        }

        base.Dispose(disposing);
    }
}