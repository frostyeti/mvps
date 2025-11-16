using System.ComponentModel;
using System.Runtime.Versioning;

using FrostYeti.IO;

namespace FrostYeti;

public static partial class Shell
{
    public static partial class Fs
    {

        [UnsupportedOSPlatform("windows")]
        public static void Chmod(IEnumerable<string> paths, UnixFileMode mode, bool recursive = false)
        {
            if (!OperatingSystem.IsWindows())
                throw new PlatformNotSupportedException("Chmod is not supported on Windows.");

            if (paths is null)
                throw new ArgumentNullException(nameof(paths), "Argument 'paths' must not be null.");

            foreach (var target in paths)
            {
                var path = target;
                if (path.IsNullOrWhiteSpace())
                    throw new ArgumentException("Paths cannot have a null or empty.", nameof(paths));

                path = ResolvePath(path);
                FileSystem.Chmod(path, mode, recursive);
            }
        }

        [UnsupportedOSPlatform("windows")]
        public static void Chmod(string path, UnixFileMode mode, bool recursive = false)
        {
            if (!OperatingSystem.IsWindows())
                throw new PlatformNotSupportedException("Chmod is not supported on Windows.");

            if (path.IsNullOrWhiteSpace())
                throw new ArgumentNullException(nameof(path), "Path cannot be null or empty.");

            path = ResolvePath(path);
            FileSystem.Chmod(path, mode, recursive);
        }

        [UnsupportedOSPlatform("windows")]
        public static void Chmod(IEnumerable<string> paths, int octal, bool recursive = false)
        {
            if (paths is null)
                throw new ArgumentNullException(nameof(paths), "Argument 'paths' must not be null.");

            foreach (var target in paths)
            {
                var path = target;
                if (path.IsNullOrWhiteSpace())
                    throw new ArgumentException("Paths cannot have a null or empty.", nameof(paths));

                path = ResolvePath(path);
                FileSystem.Chmod(path, octal, recursive);
            }
        }

        [UnsupportedOSPlatform("windows")]
        public static void Chmod(string path, int octal, bool recursive = false)
        {
            if (!OperatingSystem.IsWindows())
                throw new PlatformNotSupportedException("Chmod is not supported on Windows.");

            if (path.IsNullOrWhiteSpace())
                throw new ArgumentNullException(nameof(path), "Path cannot be null or empty.");

            path = ResolvePath(path);
            FileSystem.Chmod(path, octal, recursive);
        }

        [UnsupportedOSPlatform("windows")]
        public static void Chown(IEnumerable<string> paths, int userId, int groupId, bool recursive = false)
        {
            if (!OperatingSystem.IsWindows())
                throw new PlatformNotSupportedException("Chown is not supported on Windows.");

            if (paths is null)
                throw new ArgumentNullException(nameof(paths), "Argument 'paths' must not be null.");

            foreach (var target in paths)
            {
                var path = target;
                if (path.IsNullOrWhiteSpace())
                    throw new ArgumentException("Paths cannot have a null or empty.", nameof(paths));

                path = ResolvePath(path);
                FileSystem.Chown(path, userId, groupId, recursive);
            }
        }

        [UnsupportedOSPlatform("windows")]
        public static void Chown(string path, int userId, int groupId, bool recursive = false)
        {
            if (!OperatingSystem.IsWindows())
                throw new PlatformNotSupportedException("Chown is not supported on Windows.");

            if (path.IsNullOrWhiteSpace())
                throw new ArgumentNullException(nameof(path), "Path cannot be null or empty.");

            path = ResolvePath(path);
            FileSystem.Chown(path, userId, groupId, recursive);
        }

        [UnsupportedOSPlatform("windows")]
        public static void Chown(IEnumerable<string> paths, string userName, string groupName, bool recursive = false)
        {
            if (!OperatingSystem.IsWindows())
                throw new PlatformNotSupportedException("Chown is not supported on Windows.");

            if (paths is null)
                throw new ArgumentNullException(nameof(paths), "Argument 'paths' must not be null.");

            foreach (var target in paths)
            {
                var path = target;
                if (path.IsNullOrWhiteSpace())
                    throw new ArgumentException("Paths cannot have a null or empty.", nameof(paths));

                path = ResolvePath(path);
                FileSystem.Chown(path, userName, groupName, recursive);
            }
        }

        [UnsupportedOSPlatform("windows")]
        public static void Chown(string path, string userName, string groupName, bool recursive = false)
        {
            if (!OperatingSystem.IsWindows())
                throw new PlatformNotSupportedException("Chown is not supported on Windows.");

            if (path.IsNullOrWhiteSpace())
                throw new ArgumentNullException(nameof(path), "Path cannot be null or empty.");

            path = ResolvePath(path);
            FileSystem.Chown(path, userName, groupName, recursive);
        }

        public static void CopyFile(string source, string destination, bool overwrite = false)
        {
            if (source.IsNullOrWhiteSpace())
                throw new ArgumentNullException(nameof(source), "Source path cannot be null or empty.");
            if (destination.IsNullOrWhiteSpace())
                throw new ArgumentNullException(nameof(destination), "Destination path cannot be null or empty.");

            source = ResolvePath(source);
            destination = ResolvePath(destination);
            File.Copy(source, destination, overwrite);
        }

        public static void CopyFile(IEnumerable<string> sources, string destination, bool overwrite = false)
        {
            if (sources is null)
                throw new ArgumentNullException(nameof(sources), "Argument 'sources' must not be null.");
            if (destination.IsNullOrWhiteSpace())
                throw new ArgumentNullException(nameof(destination), "Destination path cannot be null or empty.");

            destination = ResolvePath(destination);
            foreach (var source in sources)
            {
                if (source.IsNullOrWhiteSpace())
                    throw new ArgumentException("Sources cannot have a null or empty.", nameof(sources));

                var resolvedSource = ResolvePath(source);
                File.Copy(resolvedSource, destination, overwrite);
            }
        }

        public static void CopyDir(string source, string destination, bool overwrite = false)
        {
            if (source.IsNullOrWhiteSpace())
                throw new ArgumentNullException(nameof(source), "Source path cannot be null or empty.");
            if (destination.IsNullOrWhiteSpace())
                throw new ArgumentNullException(nameof(destination), "Destination path cannot be null or empty.");

            source = ResolvePath(source);
            destination = ResolvePath(destination);
            FileSystem.CopyDir(source, destination, overwrite);
        }

        public static void Copy(string source, string destination, bool overwrite = false)
        {
            if (source.IsNullOrWhiteSpace())
                throw new ArgumentNullException(nameof(source), "Source path cannot be null or empty.");
            if (destination.IsNullOrWhiteSpace())
                throw new ArgumentNullException(nameof(destination), "Destination path cannot be null or empty.");

            source = ResolvePath(source);
            destination = ResolvePath(destination);

            if (File.Exists(source))
            {
                File.Copy(source, destination, overwrite);
            }
            else if (Directory.Exists(source))
            {
                FileSystem.CopyDir(source, destination, overwrite);
            }
            else
            {
                throw new FileNotFoundException($"Source '{source}' does not exist.");
            }
        }

        public static bool FileExists(string path)
        {
            if (path.IsNullOrWhiteSpace())
                throw new ArgumentNullException(nameof(path), "Path cannot be null or empty.");

            path = ResolvePath(path);
            return File.Exists(path);
        }

        public static bool DirExists(string path)
        {
            if (path.IsNullOrWhiteSpace())
                throw new ArgumentNullException(nameof(path), "Path cannot be null or empty.");

            path = ResolvePath(path);
            return Directory.Exists(path);
        }

        public static bool Exists(string path)
        {
            if (path.IsNullOrWhiteSpace())
                throw new ArgumentNullException(nameof(path), "Path cannot be null or empty.");

            path = Env.Expand(path);
            path = Path.GetFullPath(path);
#if NET8_0_OR_GREATER
            return Path.Exists(path);
#else
            return File.Exists(path) || Directory.Exists(path);
#endif
        }

        public static void MakeDir(string path, bool recursive = false, UnixFileMode? mode = null)
        {
            if (path.IsNullOrWhiteSpace())
                throw new ArgumentNullException(nameof(path), "Path cannot be null or empty.");

            MakeDir([path], recursive, mode);
        }

        /// <summary>
        /// Makes a new directory at the specified path.
        /// </summary>
        /// <param name="paths">
        /// The path to the directory to create.
        /// </param>
        /// <param name="recursive">
        /// If true, creates all directories in the specified path.
        /// </param>
        /// <param name="mode">Unix file mode. This is ignored on versions of .NET lower than .NET 8.</param>
        public static void MakeDir(IEnumerable<string> paths, bool recursive = false, UnixFileMode? mode = null)
        {
            foreach (var target in paths)
            {
                var path = target;
                if (path.IsNullOrWhiteSpace())
                    throw new ArgumentNullException(nameof(paths), "Paths cannot have a null or empty.");

                path = ResolvePath(path);
#if NET8_0_OR_GREATER

                if (!recursive)
                {
                    var parent = Path.GetDirectoryName(path);
                    if (parent is not null && !Directory.Exists(parent))
                    {
                        throw new DirectoryNotFoundException($"Unable to create directory '{path}': Parent directory '{parent}' does not exist.");
                    }

                    if (mode.HasValue)
                        Directory.CreateDirectory(path, mode.Value);
                    else
                        Directory.CreateDirectory(path);

                    return;
                }

                if (mode.HasValue)
                    Directory.CreateDirectory(path, mode.Value);
                else
                    Directory.CreateDirectory(path);
#else
                if (!recursive)
                {
                    var parent = Path.GetDirectoryName(path);
                    if (parent is not null && !Directory.Exists(parent))
                    {
                        throw new DirectoryNotFoundException($"Unable to create directory '{path}': Parent directory '{parent}' does not exist.");
                    }

                    Directory.CreateDirectory(path);
                    return;
                }

                Directory.CreateDirectory(path);
#endif
            }
        }

        public static void MoveFile(string source, string destination, bool overwrite = false)
        {
            if (source.IsNullOrWhiteSpace())
                throw new ArgumentNullException(nameof(source), "Source path cannot be null or empty.");
            if (destination.IsNullOrWhiteSpace())
                throw new ArgumentNullException(nameof(destination), "Destination path cannot be null or empty.");

            source = ResolvePath(source);
            destination = ResolvePath(destination);

            if (File.Exists(destination) && !overwrite)
                throw new IOException($"Destination file '{destination}' already exists and overwrite is not allowed.");

            File.Move(source, destination);
        }

        public static void MoveDir(string source, string destination, bool overwrite = false)
        {
            if (source.IsNullOrWhiteSpace())
                throw new ArgumentNullException(nameof(source), "Source path cannot be null or empty.");
            if (destination.IsNullOrWhiteSpace())
                throw new ArgumentNullException(nameof(destination), "Destination path cannot be null or empty.");

            source = ResolvePath(source);
            destination = ResolvePath(destination);

            if (Directory.Exists(destination) && !overwrite)
                throw new IOException($"Destination directory '{destination}' already exists and overwrite is not allowed.");

            Directory.Move(source, destination);
        }

        public static void Move(string source, string destination, bool overwrite = false)
        {
            if (source.IsNullOrWhiteSpace())
                throw new ArgumentNullException(nameof(source), "Source path cannot be null or empty.");
            if (destination.IsNullOrWhiteSpace())
                throw new ArgumentNullException(nameof(destination), "Destination path cannot be null or empty.");

            source = ResolvePath(source);
            destination = ResolvePath(destination);

            if (File.Exists(source))
            {
                MoveFile(source, destination, overwrite);
            }
            else if (Directory.Exists(source))
            {
                MoveDir(source, destination, overwrite);
            }
            else
            {
                throw new FileNotFoundException($"Source '{source}' does not exist.");
            }
        }

        public static void Remove(string path)
        {
            if (path.IsNullOrWhiteSpace())
                throw new ArgumentNullException(nameof(path), "Path cannot be null or empty.");

            path = ResolvePath(path);

            var attr = File.GetAttributes(path);
            if ((attr & FileAttributes.Directory) == FileAttributes.Directory)
            {
                // It's a directory
                Directory.Delete(path, true);
            }
            else
            {
                // It's a file
                File.Delete(path);
            }
        }

        public static void Remove(IEnumerable<string> paths, bool recursive = false)
        {
            if (paths is null)
                throw new ArgumentNullException(nameof(paths), "Argument 'paths' must not be null.");

            foreach (var target in paths)
            {
                var path = target;
                if (path.IsNullOrWhiteSpace())
                    throw new ArgumentException("Paths cannot have a null or empty.", nameof(paths));

                path = ResolvePath(path);

                try
                {
                    var attr = File.GetAttributes(path);
                    if ((attr & FileAttributes.Directory) == FileAttributes.Directory)
                    {
                        // It's a directory
                        if (recursive)
                        {
                            Directory.Delete(path, true);
                        }
                        else
                        {
                            Directory.Delete(path);
                        }
                    }
                    else
                    {
                        File.Delete(path);
                    }
                }
                catch (Exception ex)
                {
                    throw new IOException($"Failed to remove '{path}': {ex.Message}", ex);
                }
            }
        }

        public static void RemoveFile(string path)
        {
            if (path.IsNullOrWhiteSpace())
                throw new ArgumentNullException(nameof(path), "Path cannot be null or empty.");

            path = ResolvePath(path);

            if (!File.Exists(path))
                throw new FileNotFoundException($"File '{path}' does not exist.");

            File.Delete(path);
        }

        public static void RemoveFile(IEnumerable<string> files)
        {
            foreach (var file in files)
            {
                if (file.IsNullOrWhiteSpace())
                    throw new ArgumentNullException(nameof(files), "Files cannot have a null or empty.");

                var path = ResolvePath(file);

                if (!File.Exists(path))
                    throw new FileNotFoundException($"File '{path}' does not exist.");

                File.Delete(path);
            }
        }

        public static void RemoveDir(string path, bool recursive = false)
        {
            if (path.IsNullOrWhiteSpace())
                throw new ArgumentNullException(nameof(path), "Path cannot be null or empty.");

            path = ResolvePath(path);

            if (!Directory.Exists(path))
                throw new DirectoryNotFoundException($"Directory '{path}' does not exist.");

            if (recursive)
            {
                Directory.Delete(path, true);
            }
            else
            {
                Directory.Delete(path);
            }
        }

        public static void RemoveDir(IEnumerable<string> dirs, bool recursive = false)
        {
            foreach (var dir in dirs)
            {
                if (dir.IsNullOrWhiteSpace())
                    throw new ArgumentNullException(nameof(dirs), "Directories cannot have a null or empty.");

                var path = ResolvePath(dir);

                if (!Directory.Exists(path))
                    throw new DirectoryNotFoundException($"Directory '{path}' does not exist.");

                if (recursive)
                {
                    Directory.Delete(path, true);
                }
                else
                {
                    Directory.Delete(path);
                }
            }
        }

        public static void Touch(string path, bool create = true, bool updateAccess = true, bool updateModify = true)
        {
            if (path.IsNullOrWhiteSpace())
                throw new ArgumentNullException(nameof(path), "Path cannot be null or empty.");

            Touch([path], create, updateAccess, updateModify);
        }

        public static void Touch(IEnumerable<string> paths, bool create = true, bool updateAccess = true, bool updateModify = true)
        {
            if (paths is null)
                throw new ArgumentNullException(nameof(paths), "Argument 'paths' must not be null.");

            int index = 0;
            foreach (var target in paths)
            {
                var path = target;
                if (path.IsNullOrWhiteSpace())
                    throw new ArgumentException($"The argument 'paths' in method Touch contains a null or empty value at index {index}.", nameof(paths));

                index++;
                path = ResolvePath(path);
                var fi = new FileInfo(path);
                if (create && !fi.Exists)
                {
                    using (fi.Create())
                    {
                        // File created
                    }
                }
                else if (fi.Exists && (updateAccess || updateModify))
                {
                    var now = DateTime.UtcNow;
                    if (updateAccess)
                        fi.LastAccessTimeUtc = now;
                    if (updateModify)
                        fi.LastWriteTimeUtc = now;
                }
            }
        }
    }
}