using System.Runtime.CompilerServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;

using FrostYeti.Extras;
using FrostYeti.Results;

using static FrostYeti.Results.ValueResult;

namespace FrostYeti.IO;

/// <summary>
/// The file system class is a static class that acts as a module for file system ("fs")
/// operations that provides a single point of access rather than having to use the
/// File and Directory classes directly.  It can be used with <c>using static FrostYeti.IO.FileSystem;</c>
/// to simplify the code and make it more readable.
/// </summary>
public static partial class FileSystem
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void AppendFileText(string path, string contents)
        => System.IO.File.AppendAllText(path, contents);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void AppendFileText(string path, string contents, System.Text.Encoding encoding)
        => System.IO.File.AppendAllText(path, contents, encoding);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void AppendFileLines(string path, IEnumerable<string> contents)
        => System.IO.File.AppendAllLines(path, contents);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void AppendFileLines(string path, IEnumerable<string> contents, System.Text.Encoding encoding)
        => System.IO.File.AppendAllLines(path, contents, encoding);

    [UnsupportedOSPlatform("windows")]
    public static void Chown(string path, int userId, int groupId, bool recursive = false)
    {
        if (OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Chown is not supported on Windows.");

        int result = 0;
        if (!recursive)
        {
            result = FFI.Libc.chown(path, (uint)userId, (uint)groupId);
            if (result != 0)
            {
                var message = FFI.Sys.StrError(result);
                throw new IOException($"Failed to change ownership of '{path}': {message}", result);
            }

            return;
        }

        result = FFI.Libc.chown(path, (uint)userId, (uint)groupId);
        if (result != 0)
        {
            var message = FFI.Sys.StrError(result);
            throw new IOException($"Failed to change ownership of '{path}': {message}", result);
        }

        var attr = File.GetAttributes(path);
        if (attr.HasFlag(FileAttributes.Directory))
        {
            var files = Directory.EnumerateFiles(path);
            foreach (var file in files)
            {
                result = FFI.Libc.chown(file, (uint)userId, (uint)groupId);
                if (result != 0)
                {
                    var message = FFI.Sys.StrError(result);
                    throw new IOException($"Failed to change ownership of '{file}': {message}", result);
                }
            }

            var directories = Directory.EnumerateDirectories(path);
            foreach (var directory in directories)
            {
                result = FFI.Libc.chown(directory, (uint)userId, (uint)groupId);
                if (result != 0)
                {
                    var message = FFI.Sys.StrError(result);
                    throw new IOException($"Failed to change ownership of '{directory}': {message}", result);
                }
            }
        }
    }

    [UnsupportedOSPlatform("windows")]
    public static void Chown(string path, int userId, bool recursive = false)
    {
        if (OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Chown is not supported on Windows.");

        Chown(path, userId, userId, recursive);
    }

    [UnsupportedOSPlatform("windows")]
    public static void Chown(string path, string userName, string groupName, bool recursive = false)
    {
        if (OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Chown is not supported on Windows.");

        uint? userId = FFI.Sys.GetUserId(userName);
        if (!userId.HasValue)
            throw new ArgumentException($"Invalid user name: {userName}");

        uint? groupId = FFI.Libc.GetGroupId(groupName);

        if (!groupId.HasValue)
            throw new ArgumentException($"Invalid group name: {groupName}");

        Chown(path, (int)userId.Value, (int)groupId.Value, recursive);
    }

    [UnsupportedOSPlatform("windows")]
    public static void Chown(string path, string userName, bool recursive = false)
    {
        if (OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Chown is not supported on Windows.");

        uint? userId = FFI.Sys.GetUserId(userName);
        if (!userId.HasValue)
            throw new ArgumentException($"Invalid user name: {userName}");

        Chown(path, (int)userId.Value, recursive);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void CopyFile(string sourceFileName, string destFileName)
        => System.IO.File.Copy(sourceFileName, destFileName);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void CopyFile(string sourceFileName, string destFileName, bool overwrite)
        => System.IO.File.Copy(sourceFileName, destFileName, overwrite);

    public static void CopyDir(string sourceDirName, string destDirName, bool recursive = false)
    {
        if (sourceDirName.IsNullOrWhiteSpace())
            throw new ArgumentNullException(nameof(sourceDirName), "Source directory name cannot be null or empty.");

        if (destDirName.IsNullOrWhiteSpace())
            throw new ArgumentNullException(nameof(destDirName), "Destination directory name cannot be null or empty.");

        var src = new DirectoryInfo(sourceDirName);
        if (!src.Exists)
            throw new DirectoryNotFoundException($"Source directory not found: {sourceDirName}");

        if (!(src.Attributes & FileAttributes.Directory).HasFlag(FileAttributes.Directory))
            throw new IOException($"Source path is not a directory: {sourceDirName}");

        var dest = new DirectoryInfo(destDirName);
        if (!dest.Exists)
        {
            dest.Create();
        }
        else if (dest.Exists && !dest.Attributes.HasFlag(FileAttributes.Directory))
        {
            throw new IOException($"Destination path already exists and is not a directory: {destDirName}");
        }

        foreach (var file in src.GetFiles())
        {
            var destFile = System.IO.Path.Combine(destDirName, file.Name);
            file.CopyTo(destFile);
        }

        if (recursive)
        {
            foreach (var dir in src.GetDirectories())
            {
                var destSubDir = System.IO.Path.Combine(destDirName, dir.Name);
                CopyDir(dir.FullName, destSubDir, true);
            }
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool DirExists(string path)
        => System.IO.Directory.Exists(path);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool FileExists(string path)
        => System.IO.File.Exists(path);

    public static unsafe DirectoryInfo MakeTempDir(string? prefix = default)
        => Directory.CreateTempSubdirectory(prefix);

    [UnsupportedOSPlatform("windows")]
    public static string? GetUnixGroupName(int groupId)
    {
        if (OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("GetUnixGroupName is not supported on Windows.");

        if (groupId < 0)
            throw new ArgumentOutOfRangeException(nameof(groupId), "Group ID must be a non-negative integer.");

        var gid = (uint)groupId;
        return FFI.Libc.GetGroupName(gid);
    }

    [UnsupportedOSPlatform("windows")]
    public static int? GetUnixGroupId(string groupName)
    {
        if (OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("GetUnixGroupName is not supported on Windows.");

        var gid = FFI.Libc.GetGroupId(groupName);
        return gid.HasValue ? (int?)gid.Value : null;
    }

    [UnsupportedOSPlatform("windows")]
    public static int? GetUnixUserId(string username)
    {
        if (OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("GetUnixUserName is not supported on Windows.");

        var uid = FFI.Sys.GetUserId(username);
        return uid.HasValue ? (int?)uid.Value : null;
    }

    [UnsupportedOSPlatform("windows")]
    public static string? GetUnixUserName(int userId)
    {
        if (OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("GetUnixUserName is not supported on Windows.");

        if (userId < 0)
            throw new ArgumentOutOfRangeException(nameof(userId), "User ID must be a non-negative integer.");

        var uid = (uint)userId;

        return FFI.Sys.GetUserName(uid);
    }

    [UnsupportedOSPlatform("windows")]
    public static UnixFileStatus LStat(string path)
    {
        if (OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Stat is not supported on Windows.");

        var fileInfo = new FileInfo(path);
        if (!fileInfo.Exists)
            throw new FileNotFoundException($"File not found: {path}");

        var result = FFI.Sys.lstat(path, out var stat);
        if (result != 0)
        {
            var message = FFI.Sys.StrError(result);
            throw new IOException($"Failed to stat file '{path}': {message}", result);
        }

        return new UnixFileStatus(path, stat);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void MakeDir(string path)
        => System.IO.Directory.CreateDirectory(path);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void MoveDir(string sourceDirName, string destDirName)
        => System.IO.Directory.Move(sourceDirName, destDirName);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void MoveFile(string sourceFileName, string destFileName)
        => System.IO.File.Move(sourceFileName, destFileName);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static FileStream OpenFileStream(string path, FileMode mode)
        => System.IO.File.Open(path, mode);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static FileStream OpenFileStream(string path, FileMode mode, FileAccess access)
        => System.IO.File.Open(path, mode, access);

    public static FileStream OpenFileStream(string path, FileMode mode, FileAccess access, FileShare share)
        => System.IO.File.Open(path, mode, access, share);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static FileStream OpenReadFileStream(string path)
        => System.IO.File.OpenRead(path);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static FileStream OpenWriteFileStream(string path)
        => System.IO.File.OpenWrite(path);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static IEnumerable<FileSystemInfo> ReadDir(string path)
    {
        var dirInfo = new DirectoryInfo(path);
        if (!dirInfo.Exists)
            throw new DirectoryNotFoundException($"Directory not found: {path}");

        return dirInfo.EnumerateFileSystemInfos();
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static IEnumerable<FileSystemInfo> ReadDir(string path, string searchPattern)
    {
        var dirInfo = new DirectoryInfo(path);
        if (!dirInfo.Exists)
            throw new DirectoryNotFoundException($"Directory not found: {path}");

        return dirInfo.EnumerateFileSystemInfos(searchPattern);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static IEnumerable<FileSystemInfo> ReadDir(string path, string searchPattern, SearchOption searchOption)
    {
        var dirInfo = new DirectoryInfo(path);
        if (!dirInfo.Exists)
            throw new DirectoryNotFoundException($"Directory not found: {path}");

        return dirInfo.EnumerateFileSystemInfos(searchPattern, searchOption);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]

    public static string ReadFileText(string path)
        => System.IO.File.ReadAllText(path);

    public static string ReadFileText(string path, System.Text.Encoding encoding)
        => System.IO.File.ReadAllText(path, encoding);

    public static IEnumerable<string> ReadFileLines(string path)
        => System.IO.File.ReadAllLines(path);

    public static IEnumerable<string> ReadFileLines(string path, System.Text.Encoding encoding)
        => System.IO.File.ReadAllLines(path, encoding);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static FileInfo GetFileInfo(string path)
        => new FileInfo(path);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static DirectoryInfo GetDirInfo(string path)
        => new DirectoryInfo(path);

    public static UnixFileStatus Stat(string path)
    {
        var fileInfo = new FileInfo(path);
        if (!fileInfo.Exists)
            throw new FileNotFoundException($"File not found: {path}");

        if (OperatingSystem.IsWindows())
        {
            return new UnixFileStatus(path, fileInfo);
        }

        var result = FFI.Sys.stat(path, out var stat);
        if (result != 0)
        {
            var message = FFI.Sys.StrError(result);
            throw new IOException($"Failed to stat file '{path}': {message}", result);
        }

        return new UnixFileStatus(path, stat);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void RemoveDir(string path)
        => System.IO.Directory.Delete(path);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void RemoveDir(string path, bool recursive)
        => System.IO.Directory.Delete(path, recursive);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void RemoveFile(string path)
        => System.IO.File.Delete(path);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void WriteFile(string path, byte[] bytes)
        => System.IO.File.WriteAllBytes(path, bytes);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void WriteFileText(string path, string contents)
        => System.IO.File.WriteAllText(path, contents);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void WriteFileText(string path, string contents, System.Text.Encoding encoding)
        => System.IO.File.WriteAllText(path, contents, encoding);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void WriteFileLines(string path, IEnumerable<string> contents)
        => System.IO.File.WriteAllLines(path, contents);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void WriteFileLines(string path, IEnumerable<string> contents, System.Text.Encoding encoding)
        => System.IO.File.WriteAllLines(path, contents, encoding);

    public static ValueResult TryAppendFileText(string path, string contents)
    {
        try
        {
            System.IO.File.AppendAllText(path, contents);
            return OkRef();
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    public static ValueResult TryAppendFileText(string path, string contents, System.Text.Encoding encoding)
    {
        try
        {
            System.IO.File.AppendAllText(path, contents, encoding);
            return OkRef();
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    public static ValueResult TryAppendFileLines(string path, IEnumerable<string> contents)
    {
        try
        {
            System.IO.File.AppendAllLines(path, contents);
            return OkRef();
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    public static ValueResult TryAppendFileLines(string path, IEnumerable<string> contents, System.Text.Encoding encoding)
    {
        try
        {
            System.IO.File.AppendAllLines(path, contents, encoding);
            return OkRef();
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    public static ValueResult TryCopyFile(string sourceFileName, string destFileName)
    {
        try
        {
            System.IO.File.Copy(sourceFileName, destFileName);
            return OkRef();
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    public static ValueResult TryCopyFile(string sourceFileName, string destFileName, bool overwrite)
    {
        try
        {
            System.IO.File.Copy(sourceFileName, destFileName, overwrite);
            return OkRef();
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    public static ValueResult TryCopyDir(string sourceDirName, string destDirName, bool recursive = false)
    {
        if (sourceDirName.IsNullOrWhiteSpace())
            return new ArgumentNullException(nameof(sourceDirName), "Source directory name cannot be null or empty.");

        if (destDirName.IsNullOrWhiteSpace())
            return new ArgumentNullException(nameof(destDirName), "Destination directory name cannot be null or empty.");

        try
        {
            var src = new DirectoryInfo(sourceDirName);
            if (!src.Exists)
                return new DirectoryNotFoundException($"Source directory not found: {sourceDirName}");

            if (!(src.Attributes & FileAttributes.Directory).HasFlag(FileAttributes.Directory))
                return new IOException($"Source path is not a directory: {sourceDirName}");

            var dest = new DirectoryInfo(destDirName);
            if (!dest.Exists)
            {
                dest.Create();
            }
            else if (dest.Exists && !dest.Attributes.HasFlag(FileAttributes.Directory))
            {
                return new IOException($"Destination path already exists and is not a directory: {destDirName}");
            }

            foreach (var file in src.GetFiles())
            {
                var destFile = System.IO.Path.Combine(destDirName, file.Name);
                file.CopyTo(destFile);
            }

            foreach (var dir in src.GetDirectories())
            {
                var destSubDir = System.IO.Path.Combine(destDirName, dir.Name);
                var result = TryCopyDir(dir.FullName, destSubDir, true);
                if (!result.IsOk)
                {
                    return result;
                }
            }

            return OkRef();
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    public static ValueResult<bool> TryDirExists(string path)
    {
        try
        {
            return Directory.Exists(path);
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    public static ValueResult<bool> TryFileExists(string path)
    {
        try
        {
            return System.IO.File.Exists(path);
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    public static ValueResult<DirectoryInfo> TryMakeDir(string path)
    {
        try
        {
            return Directory.CreateDirectory(path);
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    public static ValueResult TryMoveDir(string sourceDirName, string destDirName)
    {
        try
        {
            Directory.Move(sourceDirName, destDirName);
            return OkRef();
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    public static ValueResult<FileStream> TryOpenFileStream(string path, FileMode mode)
    {
        try
        {
            return File.Open(path, mode);
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    public static ValueResult<FileStream> TryOpenFileStream(string path, FileMode mode, FileAccess access)
    {
        try
        {
            return File.Open(path, mode, access);
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    public static ValueResult<FileStream> TryOpenFileStream(string path, FileMode mode, FileAccess access, FileShare share)
    {
        try
        {
            return File.Open(path, mode, access, share);
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    public static ValueResult<FileStream> TryOpenReadFileStream(string path)
    {
        try
        {
            return File.OpenRead(path);
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    public static ValueResult<FileStream> TryOpenWriteFileStream(string path)
    {
        try
        {
            return File.OpenWrite(path);
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    public static ValueResult<IEnumerable<FileSystemInfo>> TryReadDir(string path)
    {
        try
        {
            var dirInfo = new DirectoryInfo(path);
            if (!dirInfo.Exists)
                throw new DirectoryNotFoundException($"Directory not found: {path}");

            return OkRef(dirInfo.EnumerateFileSystemInfos());
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ValueResult<IEnumerable<FileSystemInfo>> TryReadDir(string path, string searchPattern)
    {
        try
        {
            var dirInfo = new DirectoryInfo(path);
            if (!dirInfo.Exists)
                throw new DirectoryNotFoundException($"Directory not found: {path}");

            return OkRef(dirInfo.EnumerateFileSystemInfos(searchPattern));
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ValueResult<IEnumerable<FileSystemInfo>> TryReadDir(string path, string searchPattern, SearchOption searchOption)
    {
        try
        {
            var dirInfo = new DirectoryInfo(path);
            if (!dirInfo.Exists)
                throw new DirectoryNotFoundException($"Directory not found: {path}");

            return OkRef(dirInfo.EnumerateFileSystemInfos(searchPattern, searchOption));
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ValueResult<string> TryReadFileText(string path)
    {
        try
        {
            return File.ReadAllText(path);
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    public static ValueResult<string> TryReadFileText(string path, System.Text.Encoding encoding)
    {
        try
        {
            return File.ReadAllText(path, encoding);
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    public static ValueResult<IEnumerable<string>> TryReadFileLines(string path)
    {
        try
        {
            return OkRef(File.ReadLines(path));
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    public static ValueResult<IEnumerable<string>> TryReadFileLines(string path, System.Text.Encoding encoding)
    {
        try
        {
            return File.ReadAllLines(path, encoding);
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    public static ValueResult<FileInfo> TryGetFileInfo(string path)
    {
        try
        {
            return OkRef(new FileInfo(path));
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    public static ValueResult<DirectoryInfo> TryGetDirInfo(string path)
    {
        try
        {
            return OkRef(new DirectoryInfo(path));
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    public static ValueResult TryRemoveDir(string path)
    {
        try
        {
            Directory.Delete(path);
            return OkRef();
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    public static ValueResult TryRemoveDir(string path, bool recursive)
    {
        try
        {
            Directory.Delete(path, recursive);
            return OkRef();
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    public static ValueResult TryRemoveFile(string path)
    {
        try
        {
            System.IO.File.Delete(path);
            return OkRef();
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    public static ValueResult TryWriteFile(string path, byte[] bytes)
    {
        try
        {
            File.WriteAllBytes(path, bytes);
            return OkRef();
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    public static ValueResult TryWriteFileText(string path, string contents)
    {
        try
        {
            File.WriteAllText(path, contents);
            return OkRef();
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    public static ValueResult TryWriteFileText(string path, string contents, System.Text.Encoding encoding)
    {
        try
        {
            File.WriteAllText(path, contents, encoding);
            return OkRef();
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    public static ValueResult TryWriteFileLines(string path, IEnumerable<string> contents)
    {
        try
        {
            File.WriteAllLines(path, contents);
            return OkRef();
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    public static ValueResult TryWriteFileLines(string path, IEnumerable<string> contents, System.Text.Encoding encoding)
    {
        try
        {
            File.WriteAllLines(path, contents, encoding);
            return OkRef();
        }
        catch (Exception ex)
        {
            return ex;
        }
    }
}