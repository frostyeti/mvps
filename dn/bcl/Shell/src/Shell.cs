using System.Diagnostics;
using System.Runtime.Versioning;

using FrostYeti.Exec;

namespace FrostYeti;

public static partial class Shell
{
    private static readonly Lazy<string[]> s_argv = new(() =>
    {
        var args = System.Environment.GetCommandLineArgs();
        if (args.Length == 0)
            return Array.Empty<string>();

        // Remove the first argument which is the executable path
        var argv = new string[args.Length - 1];
        for (int i = 1; i < args.Length; i++)
        {
            argv[i - 1] = args[i];
        }

        return argv;
    });

    private static Lazy<bool> s_interactive = new(() =>
    {
        if (Environment.GetEnvironmentVariable("DEBIAN_FRONTEND") == "noninteractive")
            return false;

        if (Environment.GetEnvironmentVariable("CI") == "true")
            return false;

        if (Console.IsOutputRedirected)
            return false;

        if (Console.IsInputRedirected)
            return false;

        foreach (var item in Environment.GetCommandLineArgs())
        {
            if (item.EqualsFold("--non-interactive") ||
                item.EqualsFold("-NonInteractive") ||
                item.EqualFold("--quiet") ||
                item.EqualsFold("-q") ||
                item.EqualsFold("--silent"))
            {
                return false;
            }
        }

        if (!Environment.UserInteractive)
            return false;

        return true;
    });

    public static bool IsInteractive
    {
        get => s_interactive.Value;
        set => s_interactive = new Lazy<bool>(() => value);
    }

    public static bool IsProcessElevated => Environment.IsPrivilegedProcess;

    public static string[] Argv => s_argv.Value;

    public static string ExecPath => System.Environment.CommandLine;

    public static void Exit(int exitCode = 0)
    {
        if (exitCode < 0)
            throw new ArgumentOutOfRangeException(nameof(exitCode), "Exit code must be a non-negative integer.");

        System.Environment.Exit(exitCode);
    }

    public static Command Command(CommandArgs args)
        => new Command(args);

    public static Command Command(CommandOptions options)
        => new Command(options);

    /// <summary>
    /// Runs a commmand line application with arguments. The output
    /// is captured and returned.
    /// </summary>
    /// <param name="args">The command to pass in.</param>
    /// <returns>The output.</returns>
    public static Output Output(CommandArgs args)
    {
        ArgumentOutOfRangeException.ThrowIfNullOrEmpty(args);
        var exe = args[0];
        args.RemoveAt(0);
        var cmd = new Command(exe);
        return cmd.Output(args);
    }

    public static ValueTask<Output> OutputAsync(CommandArgs args, CancellationToken cancellationToken = default)
    {
        ArgumentOutOfRangeException.ThrowIfNullOrEmpty(args);
        var exe = args[0];
        args.RemoveAt(0);
        var cmd = new Command(exe);
        return cmd.OutputAsync(args, cancellationToken);
    }

    public static Output Run(CommandArgs args)
    {
        ArgumentOutOfRangeException.ThrowIfNullOrEmpty(args);
        var exe = args[0];
        args.RemoveAt(0);
        var cmd = new Command(exe);
        return cmd.Run(args);
    }

    public static ValueTask<Output> RunAsync(CommandArgs args, CancellationToken cancellationToken = default)
    {
        ArgumentOutOfRangeException.ThrowIfNullOrEmpty(args);
        var exe = args[0];
        args.RemoveAt(0);
        var cmd = new Command(exe);
        return cmd.RunAsync(args, cancellationToken);
    }

    public static BashCommand Bash()
        => new BashCommand();

    public static BashCommand Bash(string script)
        => new BashCommand(script);

    public static BunCommand Bun()
        => new BunCommand();

    public static BunCommand Bun(string script)
        => new BunCommand(script);

    [SupportedOSPlatform("windows")]
    public static WinCommand Cmd()
        => new WinCommand();

    [SupportedOSPlatform("windows")]
    public static WinCommand Cmd(string script)
        => new WinCommand(script);

    public static DenoCommand Deno()
        => new DenoCommand();

    public static DenoCommand Deno(string script)
        => new DenoCommand(script);

    public static PwshCommand Pwsh()
        => new PwshCommand();

    public static PwshCommand Pwsh(string script)
        => new PwshCommand(script);

    public static PowershellCommand Powershell()
        => new PowershellCommand();

    public static PowershellCommand Powershell(string script)
        => new PowershellCommand(script);

    public static NodeJsCommand Node()
        => new NodeJsCommand();

    public static NodeJsCommand Node(string script)
        => new NodeJsCommand(script);

    public static PythonCommand Python()
        => new PythonCommand();

    public static PythonCommand Python(string script)
        => new PythonCommand(script);

    public static RubyCommand Ruby()
        => new RubyCommand();

    public static RubyCommand Ruby(string script)
        => new RubyCommand(script);

    public static string? ReadLine()
        => Console.ReadLine();

    public static int ReadCharAsInt()
        => Console.Read();

    public static char ReadChar()
    {
        var key = Console.Read();
        if (key < 0)
            return char.MinValue;

        return (char)key;
    }

    public static ConsoleKeyInfo ReadKey()
        => Console.ReadKey();

    public static ConsoleKeyInfo ReadKey(bool intercept)
        => Console.ReadKey(intercept);

    public static string ResolvePath(string path)
    {
        if (path.Length == 1)
        {
            if (path[0] == '.')
                return System.Environment.CurrentDirectory;

            if (path[0] == '~')
            {
                var profile = Env.Vars.Home;
                if (profile.IsNullOrWhiteSpace())
                    profile = System.Environment.GetFolderPath(System.Environment.SpecialFolder.UserProfile);

                return profile;
            }

            return path;
        }

        if (path.Length == 2)
        {
            if (path[1] is '/' or '\\')
            {
                if (path[0] == '.')
                    return System.Environment.CurrentDirectory;

                if (path[0] == '~')
                {
                    var profile = Env.Vars.Home;
                    if (profile.IsNullOrWhiteSpace())
                        profile = System.Environment.GetFolderPath(System.Environment.SpecialFolder.UserProfile);

                    return profile;
                }
            }

            if (path[0] is '.' && path[1] is '.')
            {
                return Path.GetDirectoryName(System.Environment.CurrentDirectory) ?? string.Empty;
            }
        }

        if (path[1] is '/' or '\\')
        {
            if (path[0] == '.')
                path = Path.Combine(System.Environment.CurrentDirectory, path[2..]);

            if (path[0] == '~')
            {
                var profile = Env.Vars.Home;
                if (profile.IsNullOrWhiteSpace())
                    profile = System.Environment.GetFolderPath(System.Environment.SpecialFolder.UserProfile);

                path = Path.Combine(profile, path[2..]);
            }
        }

        path = Env.Expand(path);
        path = Path.GetFullPath(path);
        return path;
    }

#if NET8_0_OR_GREATER
    public static string ResolvePath(string path, string baseDir)
    {
        if (path.Length == 1)
        {
            if (path[0] == '.')
                return baseDir;

            if (path[0] == '~')
            {
                var profile = Env.Vars.Home;
                if (profile.IsNullOrWhiteSpace())
                    profile = System.Environment.GetFolderPath(System.Environment.SpecialFolder.UserProfile);

                return profile;
            }

            return path;
        }

        if (path.Length == 2)
        {
            if (path[1] is '/' or '\\')
            {
                if (path[0] == '.')
                    return baseDir;

                if (path[0] == '~')
                {
                    var profile = Env.Vars.Home;
                    if (profile.IsNullOrWhiteSpace())
                        profile = System.Environment.GetFolderPath(System.Environment.SpecialFolder.UserProfile);

                    return profile;
                }
            }

            if (path[0] is '.' && path[1] is '.')
            {
                return Path.GetDirectoryName(baseDir) ?? string.Empty;
            }
        }

        if (path[1] is '/' or '\\')
        {
            if (path[0] == '.')
                path = Path.Combine(baseDir, path[2..]);

            if (path[0] == '~')
            {
                var profile = Env.Vars.Home;
                if (profile.IsNullOrWhiteSpace())
                    profile = System.Environment.GetFolderPath(System.Environment.SpecialFolder.UserProfile);

                path = Path.Combine(profile, path[2..]);
            }
        }

        path = Env.Expand(path);
        path = Path.GetFullPath(path, baseDir);
        return path;
    }
#endif

    public static string? Which(string command, IEnumerable<string>? prependPaths = null, bool useCache = true)
        => PathFinder.Which(command, prependPaths, useCache);

    /// <summary>
    /// Finds the executable path for a given command. It uses the
    /// PathFinder to search for the executable in the system's PATH which can
    /// register path hints for specific commands.
    /// If the command is not found, it returns null.
    /// </summary>
    /// <param name="command">The executable to look for e.g. <c>dotnet</c> or <c>git.exe</c>.</param>
    /// <returns>The full path to the executable if found; otherwise, null.</returns>
    public static string? FindExe(string command)
        => PathFinder.Default.Find(command);

    public static string FindExeOrThrow(string command)
       => PathFinder.Default.FindOrThrow(command);

    public static void RegisterExePathHint(string name, Action<PathHint> registerHint)
        => PathFinder.Default.RegisterOrUpdate(name, registerHint);

    public static void SetGlobalWriteCommand(Action<ProcessStartInfo>? writeCommand)
        => Exec.Command.SetGlobalWriteCommand(writeCommand);
}