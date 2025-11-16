using System.Diagnostics;

namespace FrostYeti.IO;

public sealed class DisposableDirectory : IDisposable
{
    private readonly string directoryPath;

    private readonly Action<DisposableDirectory>? onDispose;

    private bool disposed;

    public DisposableDirectory(string directoryPath)
    {
        this.directoryPath = directoryPath;
    }

    public DisposableDirectory(string directoryPath, Action<DisposableDirectory> onDispose)
    {
        this.directoryPath = directoryPath;
        this.onDispose = onDispose;
    }

    public static implicit operator string(DisposableDirectory disposableDirectory)
    {
        return disposableDirectory?.directoryPath ?? throw new ArgumentNullException(nameof(disposableDirectory));
    }

    public static implicit operator DisposableDirectory(string directoryPath)
    {
        return new DisposableDirectory(directoryPath);
    }

    public string DirectoryPath => this.directoryPath;

    public void Dispose()
    {
        GC.SuppressFinalize(this);
        if (this.disposed)
            return;

        // Release unmanaged resources here
        if (System.IO.Directory.Exists(this.directoryPath))
        {
            System.IO.Directory.Delete(this.directoryPath, true);
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