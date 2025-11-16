namespace FrostYeti.Exec;

public sealed class BunCommand : ShellCommand<BunCommand, BunCommandOptions>
{
    public BunCommand()
    {
    }

    public BunCommand(string script)
        : this()
    {
        this.Options.Script = script;
    }

    /// <summary>
    /// Registers the bash path hint with the default path finder.
    /// </summary>
    /// <remarks>
    /// <para>
    ///   The environment variable <c>BASH_EXE</c> can be used to specify the path to the bash executable
    ///   and it takes precedence over the default paths.
    /// </para>
    /// <para>
    ///   The default paths for windows look under Program Files for Git Bun. For Linux, it
    ///   checks common locations like `/usr/bin/bash` and `/usr/local/bin/bash`.
    /// </para>
    /// </remarks>
    public static void RegisterPathHint()
    {
        PathFinder.Default.RegisterOrUpdate("bun", (hint) =>
        {
            hint.Variable = "BUN_EXE";
            hint.Linux = [
                "/usr/bin/bun",
                "/usr/local/bin/bun",
                "${HOME}/.bun/bin/bun",
                "${HOME}/.local/bin/bun",
            ];

            hint.Windows = [
                "${HOME}\\.bun\\bin\\bun.exe",
                "${LOCALAPPDATA}\\Microsoft\\WinGet\\Links\\bun.exe",
                "${LOCALAPPDATA}\\Programs\\bin\\bun.exe",
                "${HOME}\\.local\\bin\\bun.exe",
                "${ProgramFiles}\\bun\\bun.exe",
                "${ProgramFiles(x86)}\\bun\\bun.exe",
            ];
        });
    }
}