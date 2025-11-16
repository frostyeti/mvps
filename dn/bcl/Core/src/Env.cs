using System.Collections;
using System.Diagnostics.Contracts;
using System.Runtime.CompilerServices;

using FrostYeti.Extras;
using FrostYeti.Results;
using FrostYeti.Text;

using static FrostYeti.Results.Result;
using static FrostYeti.Results.ValueResult;

namespace FrostYeti;

/// <summary>
/// Provides methods for working with environment variables and the environment PATH variable.
/// </summary>
/// <remarks>
/// <para>
/// This <c>Environ</c> class is designd to be imported with the <c>using static FrostYeti.Environ;</c>
/// so that the method names do not clash with other methods and still be shorter than
/// the methods on the <see cref="Environment"/> class.
/// </para>
/// </remarks>
public static partial class Env
{
    public static EnvironmentVariables Vars { get; } = new();

    /// <summary>
    /// Appends a path to the environment variable PATH.
    /// If the path already exists in the PATH variable, it will not be added again.
    /// </summary>
    /// <param name="path">The path to append.</param>
    /// <param name="target">
    /// The target for the environment variable (e.g., process, user, machine).
    /// Default is <see cref="EnvironmentVariableTarget.Process"/>.
    /// </param>
    /// <exception cref="ArgumentNullException">
    ///    Thrown when the <paramref name="path"/> is null or empty.
    /// </exception>
    public static void AppendPath(string path, EnvironmentVariableTarget target = EnvironmentVariableTarget.Process)
    {
        ArgumentNullException.ThrowIfNullOrWhiteSpace(path, nameof(path));
        var paths = SplitPath(target);
        if (paths.Length > 0)
        {
            if (OperatingSystem.IsWindows() && paths[^1].EqualFold(path))
                return;

            if (paths[^1].Equals(path))
                return;
        }

        Array.Resize(ref paths, paths.Length + 1);
        paths[^1] = path;
        Set(OperatingSystem.IsWindows() ? "Path" : "PATH", JoinPath(paths), target);
    }

    /// <summary>
    /// Expands environment variables in a template string.
    /// </summary>
    /// <param name="template">
    /// The template string containing environment variables to expand.
    /// </param>
    /// <param name="options">
    /// The options to customize the expansion behavior.
    /// </param>
    /// <returns>
    /// A <see cref="System.ReadOnlySpan{T}"/> representing the expanded template.
    /// </returns>
    /// <exception cref="EnvironmentException">
    /// Thrown when the template contains invalid syntax.
    /// </exception>
    public static string Expand(string template, EnvExpandOptions? options = null)
        => Expand(template.AsSpan(), options).ToString();

    /// <summary>
    /// Gets the value of the specified environment variable for a specific target (e.g., process, user, machine).
    /// </summary>
    /// <param name="variable">
    ///  The name of the environment variable to retrieve.
    /// </param>
    /// <param name="target">
    /// The target for the environment variable (e.g., process, user, machine).
    /// Default is <see cref="EnvironmentVariableTarget.Process"/>.
    /// </param>
    /// <returns>
    /// The value of the environment variable, or <c>null</c> if the variable is not set or has no value.
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="variable"/> is <c>null</c>.</exception>
    /// <exception cref="ArgumentException">Thrown when the target is not valid on the os.</exception>
    /// <exception cref="System.Security.SecurityException">Thrown when the caller does not have permission to access the environment variable.</exception>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static string? Get(string variable, EnvironmentVariableTarget target = EnvironmentVariableTarget.Process)
        => Environment.GetEnvironmentVariable(variable, target);

    /// <summary>
    /// Indicates whether the specified environment variable is set for a specific target (e.g., process, user, machine).
    /// </summary>
    /// <param name="variable">
    /// The name of the environment variable to check.
    /// </param>
    /// <param name="target">
    /// The target for the environment variable (e.g., process, user, machine).
    /// The default is <see cref="EnvironmentVariableTarget.Process"/>.
    /// </param>
    /// <returns>
    /// <c>true</c> if the environment variable is set for the specified target; otherwise, <c>false</c>.
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="variable"/> is <c>null</c>.</exception>
    /// <exception cref="ArgumentException">Thrown when the target is not valid on the os.</exception>
    /// <exception cref="System.Security.SecurityException">Thrown when the caller does not have permission to access the environment variable.</exception>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool Has(string variable, EnvironmentVariableTarget target = EnvironmentVariableTarget.Process)
        => Environment.GetEnvironmentVariable(variable, target) is not null;

    /// <summary>
    /// Indicates whether the specified path exists in the environment PATH variable.
    /// </summary>
    /// <param name="path">The path to check.</param>
    /// <returns>
    /// <c>true</c> if the path exists in the environment PATH variable; otherwise, <c>false</c>.
    /// </returns>
    public static bool HasPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return false;

        var paths = SplitPath();
        return HasPath(path, paths);
    }

    public static bool HasPath(string path, EnvironmentVariableTarget target)
    {
        if (string.IsNullOrWhiteSpace(path))
            return false;

        var paths = SplitPath(target);
        return HasPath(path, paths);
    }

    /// <summary>
    /// Indicates whether the specified path exists in the provided array of paths.
    /// </summary>
    /// <param name="path">
    /// The path to check against the array of paths.
    /// </param>
    /// <param name="paths">
    /// The array of paths to check against.
    /// </param>
    /// <returns><c>true</c> if the path exists in the array; otherwise, <c>false</c>.</returns>
    public static bool HasPath(string path, string[] paths)
    {
        if (string.IsNullOrWhiteSpace(path) || paths is null || paths.Length == 0)
            return false;

        if (OperatingSystem.IsWindows())
        {
            foreach (var p in paths)
            {
                if (p.EqualsFold(path))
                    return true;
            }
        }
        else
        {
            foreach (var p in paths)
            {
                if (p.Equals(path))
                    return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Joins the specified paths into a single string, using the system's path separator.
    /// </summary>
    /// <param name="paths">
    /// The paths to join.
    /// </param>
    /// <returns>
    /// The joined string containing all the paths, separated by the system's path separator.
    /// </returns>
    public static string JoinPath(params string[] paths)
       => string.Join(System.IO.Path.PathSeparator.ToString(), paths);

    /// <summary>
    /// Prepends the specified path to the environment PATH variable.
    /// </summary>
    /// <param name="path">
    /// The path to prepend to the environment PATH variable.
    /// </param>
    /// <param name="target">
    /// The target for the environment variable (e.g., process, user, machine).
    /// Default is <see cref="EnvironmentVariableTarget.Process"/>.
    /// </param>
    public static void PrependPath(string path, EnvironmentVariableTarget target = EnvironmentVariableTarget.Process)
    {
        ArgumentNullException.ThrowIfNullOrWhiteSpace(path, nameof(path));
        var paths = SplitPath(target);
        if (paths.Length > 0)
        {
            if (OperatingSystem.IsWindows() && paths[0].EqualFold(path))
                return;

            if (paths[0].Equals(path))
                return;
        }

        var copy = new string[paths.Length + 1];
        Array.Copy(paths, 0, copy, 1, paths.Length);
        copy[0] = path;
        Set(OperatingSystem.IsWindows() ? "Path" : "PATH", JoinPath(copy), target);
    }

    /// <summary>
    /// Removes the specified path from the environment PATH variable.
    /// </summary>
    /// <param name="path">
    /// The path to remove from the environment PATH variable.
    /// </param>
    /// <param name="target">
    /// The target for the environment variable (e.g., process, user, machine).
    /// Default is <see cref="EnvironmentVariableTarget.Process"/>.
    /// </param>
    /// <exception cref="ArgumentNullException">
    /// Thrown when the <paramref name="path"/> is null or empty.
    /// </exception>
    public static void RemovePath(string path, EnvironmentVariableTarget target = EnvironmentVariableTarget.Process)
    {
        ArgumentNullException.ThrowIfNullOrWhiteSpace(path, nameof(path));

        var paths = SplitPath(target);
        var newPaths = new List<string>();

        foreach (var p in paths)
        {
            if (OperatingSystem.IsWindows() && p.EqualsFold(path))
                continue;

            if (p.Equals(path))
                continue;

            newPaths.Add(p);
        }

        if (newPaths.Count == paths.Length)
            return; // No change, path was not found.

        Set(OperatingSystem.IsWindows() ? "Path" : "PATH", JoinPath(newPaths.ToArray()), target);
    }

    /// <summary>
    /// Sets the value of the specified environment variable for a specific target (e.g., process, user, machine).
    /// </summary>
    /// <param name="variable">
    /// The name of the environment variable to set.
    /// </param>
    /// <param name="value">
    /// The value to assign to the environment variable.
    /// </param>
    /// <param name="target">
    /// The target for the environment variable (e.g., process, user, machine).
    /// Default is <see cref="EnvironmentVariableTarget.Process"/>.
    /// </param>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Set(string variable, string value, EnvironmentVariableTarget target = EnvironmentVariableTarget.Process)
        => Environment.SetEnvironmentVariable(variable, value, target);

    /// <summary>
    /// Splits the path as if it were an environment variable PATH.
    /// </summary>
    /// <param name="path">
    /// The path to split into an array of paths.
    /// </param>
    /// <returns>
    /// An array of strings representing the individual paths in the environment variable PATH.
    /// </returns>
    public static string[] SplitPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return [];

        return path.Split(new[] { System.IO.Path.PathSeparator }, StringSplitOptions.RemoveEmptyEntries);
    }

    /// <summary>
    /// Splits the environment variable PATH into an array of paths.
    /// </summary>
    /// <param name="target">
    /// The target for the environment variable (e.g., process, user, machine).
    /// Default is <see cref="EnvironmentVariableTarget.Process"/>.
    /// </param>
    /// <returns>
    /// An array of strings representing the individual paths in the environment variable PATH.
    /// </returns>
    public static string[] SplitPath(EnvironmentVariableTarget target = EnvironmentVariableTarget.Process)
        => SplitPath(Get(OperatingSystem.IsWindows() ? "Path" : "PATH", target) ?? string.Empty);

    /// <summary>
    /// Tries to append a path to the environment PATH variable.
    /// </summary>
    /// <param name="path">The path to append.</param>
    /// <param name="target">
    /// The target for the environment variable (e.g., process, user, machine).
    /// Default is <see cref="EnvironmentVariableTarget.Process"/>.
    /// </param>
    /// <returns>
    /// A <see cref="ValueResult"/> representing the outcome of the operation.
    /// </returns>
    public static ValueResult TryAppendPath(string path, EnvironmentVariableTarget target = EnvironmentVariableTarget.Process)
    {
        if (path.IsNullOrWhiteSpace())
            return new ArgumentNullException(nameof(path), "Path cannot be null or empty.");

        var pathsResult = TrySplitEnvPath(target);
        if (!pathsResult.IsOk)
            return pathsResult.Error;

        var paths = pathsResult.Value;
        if (paths.Length > 0)
        {
            if (OperatingSystem.IsWindows() && paths[^1].EqualFold(path))
                return OkRef();

            if (paths[^1].Equals(path))
                return OkRef();
        }

        Array.Resize(ref paths, paths.Length + 1);
        paths[^1] = path;
        var newPath = TryJoinEnvPath(paths);
        if (!newPath.IsOk)
            return newPath.Error;

        return TrySetEnv(OperatingSystem.IsWindows() ? "Path" : "PATH", newPath.Value, target);
    }

    /// <summary>
    /// Tries to expand environment variables in a template string.
    /// </summary>
    /// <param name="template">
    /// The template string containing environment variables to expand.
    /// </param>
    /// <param name="options">
    /// Options to customize the expansion behavior.
    /// </param>
    /// <returns>
    /// A <see cref="ValueResult{T}"/> representing the outcome of the operation.
    /// </returns>
    public static ValueResult<string> TryExpand(string template, EnvExpandOptions? options = null)
    {
        var result = TryExpand(template.AsSpan(), options);
        if (result.IsOk)
            return result.Value.Span.AsString();
        return result.Error;
    }

    /// <summary>
    /// Tries to get the value of an environment variable.
    /// </summary>
    /// <param name="variable">
    /// The name of the environment variable to retrieve.
    /// </param>
    /// <param name="target">
    /// The target for the environment variable (e.g., process, user, machine).
    /// Default is <see cref="EnvironmentVariableTarget.Process"/>.
    /// </param>
    /// <returns>
    /// A <see cref="ValueResult{T}"/> representing the outcome of the operation.
    /// </returns>
    public static ValueResult<string> TryGet(string variable, EnvironmentVariableTarget target = EnvironmentVariableTarget.Process)
    {
        if (string.IsNullOrEmpty(variable))
            return new ValueResult<string>(new EnvironmentException("Environment variable key cannot be null or empty."));

        var value = Environment.GetEnvironmentVariable(variable, target);
        if (value is null)
            return new ValueResult<string>(new EnvironmentException($"Environment variable '{variable}' is not set for target {target}."));

        return new ValueResult<string>(value);
    }

    /// <summary>
    /// Tries to check if an environment variable is set.
    /// </summary>
    /// <param name="variable">
    /// The name of the environment variable to check.
    /// </param>
    /// <param name="target">
    /// The target for the environment variable (e.g., process, user, machine).
    /// Default is <see cref="EnvironmentVariableTarget.Process"/>.
    /// </param>
    /// <returns>
    /// A <see cref="ValueResult{T}"/> representing the outcome of the operation.
    /// </returns>
    public static ValueResult<bool> TryHasEnv(string variable, EnvironmentVariableTarget target = EnvironmentVariableTarget.Process)
    {
        if (string.IsNullOrEmpty(variable))
            return new ValueResult<bool>(new EnvironmentException("Environment variable key cannot be null or empty."));

        try
        {
            var exists = Environment.GetEnvironmentVariable(variable, target) is not null;
            return new ValueResult<bool>(exists);
        }
        catch (Exception ex)
        {
            return new ValueResult<bool>(new EnvironmentException($"Failed to check environment variable '{variable}': {ex.Message}", ex));
        }
    }

    /// <summary>
    /// Tries to join the specified paths into a single string, using the system's path separator.
    /// </summary>
    /// <param name="paths">
    /// The paths to join.
    /// </param>
    /// <returns>
    /// A <see cref="ValueResult{T}"/> representing the outcome of the operation.
    /// </returns>
    public static ValueResult<string> TryJoinEnvPath(params string[] paths)
    {
        if (paths is null || paths.Length == 0)
            return string.Empty;

        try
        {
            return string.Join(System.IO.Path.PathSeparator.ToString(), paths);
        }
        catch (Exception ex)
        {
            return new EnvironmentException($"Failed to join environment variable paths: {ex.Message}", ex);
        }
    }

    /// <summary>
    /// Tries to prepend a path to the environment PATH variable.
    /// </summary>
    /// <param name="path">
    /// The path to prepend to the environment PATH variable.
    /// </param>
    /// <param name="target">
    /// The target for the environment variable (e.g., process, user, machine).
    /// Default is <see cref="EnvironmentVariableTarget.Process"/>.
    /// </param>
    /// <returns>
    /// A <see cref="ValueResult"/> representing the outcome of the operation.
    /// </returns>
    public static ValueResult TryPrependEnvPath(string path, EnvironmentVariableTarget target = EnvironmentVariableTarget.Process)
    {
        if (path.IsNullOrWhiteSpace())
            return new ArgumentNullException(nameof(path), "Path cannot be null or empty.");
        var pathsResult = TrySplitEnvPath(target);
        if (!pathsResult.IsOk)
            return pathsResult.Error;

        var paths = pathsResult.Value;
        if (paths.Length > 0)
        {
            if (OperatingSystem.IsWindows() && paths[0].EqualFold(path))
                return OkRef();

            if (paths[0].Equals(path))
                return OkRef();
        }

        var copy = new string[paths.Length + 1];
        Array.Copy(paths, 0, copy, 1, paths.Length);
        copy[0] = path;
        var newPathResult = TryJoinEnvPath(copy);
        if (!newPathResult.IsOk)
            return newPathResult.Error;

        return TrySetEnvPath(newPathResult.Value, target);
    }

    /// <summary>
    /// Tries to set the specified environment variable.
    /// </summary>
    /// <param name="variable">
    /// The name of the environment variable to set.
    /// </param>
    /// <param name="value">
    /// The value to assign to the environment variable.
    /// </param>
    /// <param name="target">
    /// The target for the environment variable (e.g., process, user, machine).
    /// </param>
    /// <returns>
    /// A <see cref="ValueResult"/> representing the outcome of the operation.
    /// </returns>
    public static ValueResult TrySetEnv(string variable, string value, EnvironmentVariableTarget target = EnvironmentVariableTarget.Process)
    {
        if (string.IsNullOrEmpty(variable))
            return new ArgumentNullException(nameof(variable), "Environment variable key cannot be null or empty.");

        if (value is null)
            return new EnvironmentException("Environment variable value cannot be null.");

        try
        {
            Environment.SetEnvironmentVariable(variable, value, target);
            return OkRef();
        }
        catch (Exception ex)
        {
            return new EnvironmentException($"Failed to set environment variable '{variable}': {ex.Message}", ex);
        }
    }

    /// <summary>
    /// Tries to set the specified environment variable path.
    /// </summary>
    /// <param name="path">
    /// The path to add to the environment variable.
    /// </param>
    /// <param name="target">
    /// The target for the environment variable (e.g., process, user, machine).
    /// </param>
    /// <returns>
    /// A <see cref="ValueResult"/> representing the outcome of the operation.
    /// </returns>
    public static ValueResult TrySetEnvPath(string path, EnvironmentVariableTarget target = EnvironmentVariableTarget.Process)
    {
        if (string.IsNullOrWhiteSpace(path))
            return new ArgumentNullException(nameof(path), "Environment variable path cannot be null or empty.");

        try
        {
            Set(OperatingSystem.IsWindows() ? "Path" : "PATH", path, target);
            return OkRef();
        }
        catch (Exception ex)
        {
            return new EnvironmentException($"Failed to set environment variable path: {ex.Message}", ex);
        }
    }

    /// <summary>
    /// Splits the path as if it were an environment variable PATH.
    /// </summary>
    /// <param name="path">
    /// The path to split into an array of paths.
    /// </param>
    /// <returns>
    /// An array of strings representing the individual paths in the environment variable PATH.
    /// </returns>
    public static ValueResult<string[]> TrySplitEnvPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return OkRef(Array.Empty<string>());

        return new ValueResult<string[]>(path.Split(new[] { System.IO.Path.PathSeparator }, StringSplitOptions.RemoveEmptyEntries));
    }

    /// <summary>
    /// Splits the environment variable PATH into an array of paths.
    /// </summary>
    /// <param name="target">
    /// The target for the environment variable (e.g., process, user, machine).
    /// Default is <see cref="EnvironmentVariableTarget.Process"/>.
    /// </param>
    /// <returns>
    /// An array of strings representing the individual paths in the environment variable PATH.
    /// </returns>
    public static ValueResult<string[]> TrySplitEnvPath(EnvironmentVariableTarget target = EnvironmentVariableTarget.Process)
    {
        var result = TryGet(OperatingSystem.IsWindows() ? "Path" : "PATH", target);
        if (result.IsError)
            return result.Error;

        return TrySplitEnvPath(result.Value);
    }

    /// <summary>
    /// Tries to unset the specified environment variable.
    /// </summary>
    /// <param name="variable">
    /// The name of the environment variable to unset.
    /// </param>
    /// <param name="target">
    /// The target for the environment variable (e.g., process, user, machine).
    /// </param>
    /// <returns>
    /// A <see cref="ValueResult"/> representing the outcome of the operation.
    /// </returns>
    public static ValueResult TryUnset(string variable, EnvironmentVariableTarget target = EnvironmentVariableTarget.Process)
    {
        if (string.IsNullOrEmpty(variable))
            return new ArgumentNullException(nameof(variable), "Environment variable key cannot be null or empty.");

        try
        {
            Environment.SetEnvironmentVariable(variable, null, target);
            return OkRef();
        }
        catch (Exception ex)
        {
            return new EnvironmentException($"Failed to unset environment variable '{variable}': {ex.Message}", ex);
        }
    }

    /// <summary>
    /// Unsets the specified environment variable.
    /// </summary>
    /// <param name="variable">
    /// The name of the environment variable to unset.
    /// </param>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void UnsetEnv(string variable)
        => Environment.SetEnvironmentVariable(variable, null);

    /// <summary>
    /// Unsets the specified environment variable.
    /// </summary>
    /// <param name="variable">
    /// The name of the environment variable to unset.
    /// </param>
    /// <param name="target">
    /// The target for the environment variable (e.g., process, user, machine).
    /// </param>
    public static void UnsetEnv(string variable, EnvironmentVariableTarget target)
        => Environment.SetEnvironmentVariable(variable, null, target);

    public static class Keys
    {
        public static string Path => OperatingSystem.IsWindows() ? "Path" : "PATH";

        public static string Home => OperatingSystem.IsWindows() ? "USERPROFILE" : "HOME";

        public static string Temp => OperatingSystem.IsWindows() ? "TEMP" : "TMPDIR";

        public static string User => OperatingSystem.IsWindows() ? "USERNAME" : "USER";

        public static string Shell => OperatingSystem.IsWindows() ? "ComSpec" : "SHELL";

        public static string HomeConfig => OperatingSystem.IsWindows() ? "APPDATA" : "XDG_CONFIG_HOME";

        public static string HomeData => OperatingSystem.IsWindows() ? "LOCALAPPDATA" : "XDG_DATA_HOME";

        public static string HomeCache => OperatingSystem.IsWindows() ? "LOCALAPPDATA" : "XDG_CACHE_HOME";
    }

    public class EnvironmentVariables : IEnumerable<KeyValuePair<string, string>>
    {
        public string? this[string key]
        {
            get => Environment.GetEnvironmentVariable(key);
            set => Environment.SetEnvironmentVariable(key, value);
        }

        public string Path
        {
            get => Environment.GetEnvironmentVariable(Keys.Path) ?? string.Empty;
            set => Environment.SetEnvironmentVariable(Keys.Path, value);
        }

        public string Home
        {
            get => Environment.GetEnvironmentVariable(Keys.Home) ?? string.Empty;
            set => Environment.SetEnvironmentVariable(Keys.Home, value);
        }

        public string Temp
        {
            get => Environment.GetEnvironmentVariable(Keys.Temp) ?? string.Empty;
            set => Environment.SetEnvironmentVariable(Keys.Temp, value);
        }

        public string User
        {
            get => Environment.GetEnvironmentVariable(Keys.User) ?? string.Empty;
            set => Environment.SetEnvironmentVariable(Keys.User, value);
        }

        public string Shell
        {
            get => Environment.GetEnvironmentVariable(Keys.Shell) ?? string.Empty;
            set => Environment.SetEnvironmentVariable(Keys.Shell, value);
        }

        public string HomeConfig
        {
            get => Environment.GetEnvironmentVariable(Keys.HomeConfig) ?? string.Empty;
            set => Environment.SetEnvironmentVariable(Keys.HomeConfig, value);
        }

        public string HomeCache
        {
            get => Environment.GetEnvironmentVariable(Keys.HomeCache) ?? string.Empty;
            set => Environment.SetEnvironmentVariable(Keys.HomeCache, value);
        }

        public IEnumerator<KeyValuePair<string, string>> GetEnumerator()
        {
            foreach (DictionaryEntry entry in Environment.GetEnvironmentVariables())
            {
                if (entry.Key is string key && entry.Value is string value)
                    yield return new KeyValuePair<string, string>(key, value);
            }
        }

        IEnumerator IEnumerable.GetEnumerator() => this.GetEnumerator();
    }
}