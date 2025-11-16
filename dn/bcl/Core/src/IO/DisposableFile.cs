using System.Diagnostics;

namespace FrostYeti.IO;

public sealed class DisposableFile : IDisposable
{
    private readonly string filePath;

    private readonly Action<DisposableFile>? onDispose;

    private bool disposed;

    public DisposableFile(string filePath)
    {
        this.filePath = filePath;
        this.onDispose = null;
    }

    public DisposableFile(string filePath, Action<DisposableFile> onDispose)
    {
        this.filePath = filePath;
        this.onDispose = onDispose;
    }

    public static implicit operator string(DisposableFile disposableFile)
    {
        return disposableFile?.filePath ?? throw new ArgumentNullException(nameof(disposableFile));
    }

    public static implicit operator DisposableFile(string filePath)
    {
        return new DisposableFile(filePath);
    }

    public string FilePath => this.filePath;

    public void Dispose()
    {
        GC.SuppressFinalize(this);
        if (this.disposed)
            return;

        // Release unmanaged resources here
        if (System.IO.File.Exists(this.filePath))
        {
            System.IO.File.Delete(this.filePath);
        }

        try
        {
            this.onDispose?.Invoke(this);
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"Error during disposal: {ex.Message} -- {ex.StackTrace}");
        }

        this.disposed = true;
    }
}