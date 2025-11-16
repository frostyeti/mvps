using System.Runtime.CompilerServices;
using System.Text;

using FrostYeti.Extras;
using FrostYeti.Results;

using static FrostYeti.Results.ValueResult;

namespace FrostYeti.IO;

public static partial class FileSystem
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void AppendFile(string path, byte[] bytes)
        => File.AppendAllBytes(path, bytes);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void AppendFile(string path, ReadOnlySpan<byte> bytes)
        => File.AppendAllBytes(path, bytes);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Task AppendFileAsync(string path, byte[] bytes, CancellationToken cancellationToken = default)
        => File.AppendAllBytesAsync(path, bytes, cancellationToken);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Task AppendFileAsync(string path, ReadOnlyMemory<byte> bytes, CancellationToken cancellationToken = default)
        => File.AppendAllBytesAsync(path, bytes, cancellationToken);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Task WriteFileAsync(string path, ReadOnlyMemory<byte> bytes, CancellationToken cancellationToken = default)
        => File.WriteAllBytesAsync(path, bytes, cancellationToken);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Task WriteFileTextAsync(string path, ReadOnlyMemory<char> contents, CancellationToken cancellationToken = default)
        => File.WriteAllTextAsync(path, contents, cancellationToken);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Task WriteFileTextAsync(string path, ReadOnlyMemory<char> contents, Encoding encoding, CancellationToken cancellationToken = default)
        => File.WriteAllTextAsync(path, contents, encoding, cancellationToken);

    public static ValueResult TryAppendFile(string path, byte[] bytes)
    {
        try
        {
            File.AppendAllBytes(path, bytes);
            return OkRef();
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    public static ValueResult TryAppendFile(string path, ReadOnlySpan<byte> bytes)
    {
        try
        {
            File.AppendAllBytes(path, bytes);
            return OkRef();
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    public static async Task<ValueResult> TryAppendFileAsync(string path, byte[] bytes, CancellationToken cancellationToken = default)
    {
        try
        {
            await File.AppendAllBytesAsync(path, bytes, cancellationToken);
            return OkRef();
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    public static async Task<ValueResult> TryAppendFileAsync(string path, ReadOnlyMemory<byte> bytes, CancellationToken cancellationToken = default)
    {
        try
        {
            await File.AppendAllBytesAsync(path, bytes, cancellationToken);
            return OkRef();
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    public static async Task<ValueResult> TryWriteFileAsync(string path, ReadOnlyMemory<byte> bytes, CancellationToken cancellationToken = default)
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

    public static async Task<ValueResult> TryWriteFileTextAsync(string path, ReadOnlyMemory<char> contents, CancellationToken cancellationToken = default)
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

    public static async Task<ValueResult> TryWriteFileTextAsync(string path, ReadOnlyMemory<char> contents, Encoding encoding, CancellationToken cancellationToken = default)
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
}