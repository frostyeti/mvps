using System.Runtime.CompilerServices;
using System.Text;

using FrostYeti.Results;

using Microsoft.Win32.SafeHandles;

using static FrostYeti.Results.ValueResult;

namespace FrostYeti.IO;

public static partial class FileSystem
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Task AppendFileTextAsync(string path, string contents, CancellationToken cancellationToken = default)
        => File.AppendAllTextAsync(path, contents, cancellationToken);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Task AppendFileTextAsync(string path, string contents, Encoding encoding, CancellationToken cancellationToken = default)
        => File.AppendAllTextAsync(path, contents, encoding, cancellationToken);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Task AppendFileLinesAsync(string path, IEnumerable<string> contents, CancellationToken cancellationToken = default)
        => File.AppendAllLinesAsync(path, contents, cancellationToken);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Task AppendFileLinesAsync(string path, IEnumerable<string> contents, Encoding encoding, CancellationToken cancellationToken = default)
        => File.AppendAllLinesAsync(path, contents, encoding, cancellationToken);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static SafeFileHandle OpenFileHandle(
        string path,
        FileMode mode = FileMode.Open,
        FileAccess access = FileAccess.Read,
        FileShare share = FileShare.Read,
        FileOptions options = FileOptions.None,
        long preallocationSize = 0)
        => File.OpenHandle(path, mode, access, share, options, preallocationSize);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Task<byte[]> ReadFileAsync(string path, CancellationToken cancellationToken = default)
        => File.ReadAllBytesAsync(path, cancellationToken);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Task<string> ReadFileTextAsync(string path, CancellationToken cancellationToken = default)
        => File.ReadAllTextAsync(path, cancellationToken);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Task<string> ReadFileTextAsync(string path, Encoding encoding, CancellationToken cancellationToken = default)
        => File.ReadAllTextAsync(path, encoding, cancellationToken);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Task WriteFileAsync(string path, byte[] bytes, CancellationToken cancellationToken = default)
        => File.WriteAllBytesAsync(path, bytes, cancellationToken);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Task WriteFileTextAsync(string path, string contents, CancellationToken cancellationToken = default)
        => File.WriteAllTextAsync(path, contents, cancellationToken);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Task WriteFileTextAsync(string path, string contents, Encoding encoding, CancellationToken cancellationToken = default)
        => File.WriteAllTextAsync(path, contents, encoding, cancellationToken);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Task WriteFileLinesAsync(string path, IEnumerable<string> contents, CancellationToken cancellationToken = default)
        => File.WriteAllLinesAsync(path, contents, cancellationToken);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Task WriteFileLinesAsync(string path, IEnumerable<string> contents, Encoding encoding, CancellationToken cancellationToken = default)
        => File.WriteAllLinesAsync(path, contents, encoding, cancellationToken);

    public static async Task<ValueResult> TryAppendFileTextAsync(string path, string contents, CancellationToken cancellationToken = default)
    {
        try
        {
            await File.AppendAllTextAsync(path, contents, cancellationToken);
            return OkRef();
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    public static async Task<ValueResult> TryAppendFileTextAsync(string path, string contents, Encoding encoding, CancellationToken cancellationToken = default)
    {
        try
        {
            await File.AppendAllTextAsync(path, contents, encoding, cancellationToken);
            return OkRef();
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    public static async Task<ValueResult> TryAppendFileLinesAsync(string path, IEnumerable<string> contents, CancellationToken cancellationToken = default)
    {
        try
        {
            await File.AppendAllLinesAsync(path, contents, cancellationToken);
            return OkRef();
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    public static async Task<ValueResult> TryAppendFileLinesAsync(string path, IEnumerable<string> contents, Encoding encoding, CancellationToken cancellationToken = default)
    {
        try
        {
            await File.AppendAllLinesAsync(path, contents, encoding, cancellationToken);
            return OkRef();
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    public static Result<SafeFileHandle> TryOpenFileHandle(
        string path,
        FileMode mode = FileMode.Open,
        FileAccess access = FileAccess.Read,
        FileShare share = FileShare.Read,
        FileOptions options = FileOptions.None,
        long preallocationSize = 0)
    {
        try
        {
            var handle = File.OpenHandle(path, mode, access, share, options, preallocationSize);
            return handle;
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    public static async Task<ValueResult<byte[]>> TryReadFileAsync(string path, CancellationToken cancellationToken = default)
    {
        try
        {
            var bytes = await File.ReadAllBytesAsync(path, cancellationToken);
            return bytes;
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    public static async Task<ValueResult<string>> TryReadFileTextAsync(string path, CancellationToken cancellationToken = default)
    {
        try
        {
            var text = await File.ReadAllTextAsync(path, cancellationToken);
            return text;
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    public static async Task<ValueResult<string>> TryReadFileTextAsync(string path, Encoding encoding, CancellationToken cancellationToken = default)
    {
        try
        {
            var text = await File.ReadAllTextAsync(path, encoding, cancellationToken);
            return text;
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    public static async Task<ValueResult> TryWriteFileAsync(string path, byte[] bytes, CancellationToken cancellationToken = default)
    {
        try
        {
            await File.WriteAllBytesAsync(path, bytes, cancellationToken);
            return OkRef();
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    public static async Task<ValueResult> TryWriteFileTextAsync(string path, string contents, CancellationToken cancellationToken = default)
    {
        try
        {
            await File.WriteAllTextAsync(path, contents, cancellationToken);
            return OkRef();
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    public static async Task<ValueResult> TryWriteFileTextAsync(string path, string contents, Encoding encoding, CancellationToken cancellationToken = default)
    {
        try
        {
            await File.WriteAllTextAsync(path, contents, encoding, cancellationToken);
            return OkRef();
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    public static async Task<ValueResult> TryWriteFileLinesAsync(string path, IEnumerable<string> contents, CancellationToken cancellationToken = default)
    {
        try
        {
            await File.WriteAllLinesAsync(path, contents, cancellationToken);
            return OkRef();
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    public static async Task<ValueResult> TryWriteFileLinesAsync(string path, IEnumerable<string> contents, Encoding encoding, CancellationToken cancellationToken = default)
    {
        try
        {
            await File.WriteAllLinesAsync(path, contents, encoding, cancellationToken);
            return OkRef();
        }
        catch (Exception ex)
        {
            return ex;
        }
    }
}