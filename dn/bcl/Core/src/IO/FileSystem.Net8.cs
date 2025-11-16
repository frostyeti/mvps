using System.Runtime.CompilerServices;
using System.Runtime.Versioning;
using System.Text;

using FrostYeti.Extras;
using FrostYeti.Results;

using static FrostYeti.Results.ValueResult;

namespace FrostYeti.IO;

public static partial class FileSystem
{
    [UnsupportedOSPlatform("windows")]
    public static void Chmod(string path, UnixFileMode mode, bool recursive = false)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Chmod is not supported on Windows.");

        File.SetUnixFileMode(path, mode);

        if (!recursive)
            return;

        if (File.GetAttributes(path).HasFlag(FileAttributes.Directory))
        {
            foreach (var file in Directory.EnumerateFiles(path))
            {
                File.SetUnixFileMode(file, mode);
            }

            foreach (var directory in Directory.EnumerateDirectories(path))
            {
                Chmod(directory, mode, true);
            }
        }
    }

    [UnsupportedOSPlatform("windows")]
    public static void Chmod(string path, int octal, bool recursive = false)
        => Chmod(path, UnixFileModeMembers.FromOctal(octal), recursive);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static FileSystemInfo? RealPathFile(string linkPath, bool returnFinalTarget = true)
       => File.ResolveLinkTarget(linkPath, returnFinalTarget);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static FileSystemInfo? RealPathDirectory(string linkPath, bool returnFinalTarget = true)
        => Directory.ResolveLinkTarget(linkPath, returnFinalTarget);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static IAsyncEnumerable<string> ReadLinesAsync(string path, CancellationToken cancellationToken = default)
        => File.ReadLinesAsync(path, cancellationToken);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static IAsyncEnumerable<string> ReadLinesAsync(string path, Encoding encoding, CancellationToken cancellationToken = default)
        => File.ReadLinesAsync(path, encoding, cancellationToken);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static FileSystemInfo SymlinkDirectory(string path, string target)
        => Directory.CreateSymbolicLink(path, target);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static FileSystemInfo SymlinkFile(string path, string target)
        => File.CreateSymbolicLink(path, target);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ValueResult TryChmod(string path, UnixFileMode mode)
    {
        try
        {
            File.SetUnixFileMode(path, mode);
            return ValueResult.OkRef();
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ValueResult TryChmod(string path, int octal)
    {
        try
        {
            File.SetUnixFileMode(path, UnixFileModeMembers.FromOctal(octal));
            return OkRef();
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ValueResult<FileSystemInfo> TryRealPathFile(string linkPath, bool returnFinalTarget = true)
    {
        try
        {
            var result = File.ResolveLinkTarget(linkPath, returnFinalTarget);
            if (result is null)
                return new ResourceNotFoundException(linkPath, "RealPath");

            return result;
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ValueResult<FileSystemInfo> TryRealPathDirectory(string linkPath, bool returnFinalTarget = true)
    {
        try
        {
            var result = Directory.ResolveLinkTarget(linkPath, returnFinalTarget);
            if (result is null)
                return new ResourceNotFoundException(linkPath, "RealPath");

            return result;
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    public static ValueResult<FileSystemInfo> TryMakeTempDirectory(string prefix)
    {
        try
        {
            var result = Directory.CreateTempSubdirectory(prefix);
            return result;
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    public static ValueResult<IAsyncEnumerable<string>> TryReadLinesAsync(string path, CancellationToken cancellationToken = default)
    {
        try
        {
            var result = File.ReadLinesAsync(path, cancellationToken);
            if (result is null)
                return new ResourceNotFoundException(path, "File");
            return new ValueResult<IAsyncEnumerable<string>>(result);
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    public static ValueResult<IAsyncEnumerable<string>> TryReadLinesAsync(string path, Encoding encoding, CancellationToken cancellationToken = default)
    {
        try
        {
            var result = File.ReadLinesAsync(path, encoding, cancellationToken);
            if (result is null)
                return new ResourceNotFoundException(path, "File");

            return new ValueResult<IAsyncEnumerable<string>>(result);
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    public static ValueResult<FileSystemInfo> TrySymlinkDirectory(string path, string target)
    {
        try
        {
            var result = Directory.CreateSymbolicLink(path, target);
            return result;
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    public static ValueResult<FileSystemInfo> TrySymlinkFile(string path, string target)
    {
        try
        {
            var result = File.CreateSymbolicLink(path, target);
            return result;
        }
        catch (Exception ex)
        {
            return ex;
        }
    }
}