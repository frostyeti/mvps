using FrostYeti.Results;

namespace FrostYeti;

public static partial class Shell
{
    private static readonly Stack<string> s_directoryStack = new Stack<string>();

    private static readonly HashSet<Action<string>> s_directoryChangeListeners = new HashSet<Action<string>>();

    public static bool AddDirectoryChangeListener(Action<string> listener)
    {
        if (listener == null)
        {
            throw new ArgumentNullException(nameof(listener), "Listener cannot be null.");
        }

        return s_directoryChangeListeners.Add(listener);
    }

    public static bool RemoveDirectoryChangeListener(Action<string> listener)
    {
        if (listener == null)
        {
            throw new ArgumentNullException(nameof(listener), "Listener cannot be null.");
        }

        return s_directoryChangeListeners.Remove(listener);
    }

    public static string Pwd()
        => Environment.CurrentDirectory;

    public static void Chdir(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new ArgumentException("Path cannot be null or whitespace.", nameof(path));
        }

        if (!Directory.Exists(path))
        {
            throw new DirectoryNotFoundException($"The directory '{path}' does not exist.");
        }

        if (path != Environment.CurrentDirectory)
        {
            foreach (var listener in s_directoryChangeListeners)
            {
                listener(path);
            }
        }

        Environment.CurrentDirectory = path;
    }

    public static void Pushd(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new ArgumentException("Path cannot be null or whitespace.", nameof(path));
        }

        if (!Directory.Exists(path))
        {
            throw new DirectoryNotFoundException($"The directory '{path}' does not exist.");
        }

        s_directoryStack.Push(Environment.CurrentDirectory);
        Chdir(path);
    }

    public static string Popd()
    {
        if (s_directoryStack.Count == 0)
        {
            throw new InvalidOperationException("No directories in stack to pop.");
        }

        var previousDirectory = Environment.CurrentDirectory;
        Chdir(s_directoryStack.Pop());
        return previousDirectory;
    }

    public static ValueResult<string> TryPopd()
    {
        if (s_directoryStack.Count == 0)
        {
            return new InvalidOperationException("No directories in stack to pop.");
        }

        var previousDirectory = Environment.CurrentDirectory;
        try
        {
            Chdir(s_directoryStack.Pop());
        }
        catch (Exception ex)
        {
            return ex;
        }

        return previousDirectory;
    }

    public static ValueResult<string> TryPushd(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return new ArgumentException("Path cannot be null or whitespace.", nameof(path));
        }

        if (!Directory.Exists(path))
        {
            return new DirectoryNotFoundException($"The directory '{path}' does not exist.");
        }

        s_directoryStack.Push(Environment.CurrentDirectory);
        try
        {
            Chdir(path);
        }
        catch (Exception ex)
        {
            return ex;
        }

        return path;
    }
}