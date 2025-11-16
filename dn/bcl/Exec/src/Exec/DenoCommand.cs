namespace FrostYeti.Exec;

public sealed class DenoCommand : ShellCommand<DenoCommand, DenoCommandOptions>
{
    public DenoCommand()
    {
    }

    public DenoCommand(string script)
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
    ///   The default paths for windows look under Program Files for Git Deno. For Linux, it
    ///   checks common locations like `/usr/bin/bash` and `/usr/local/bin/bash`.
    /// </para>
    /// </remarks>
    public static void RegisterPathHint()
    {
        PathFinder.Default.RegisterOrUpdate("deno", (hint) =>
        {
            hint.Variable = "DENO_EXE";
            hint.Linux = [
                "/usr/bin/deno",
                "/usr/local/bin/deno",
                "${HOME}/.deno/bin/deno",
                "${HOME}/.local/bin/deno",
            ];

            hint.Windows = [
                "${HOME}\\.deno\\bin\\deno.exe",
                "${LOCALAPPDATA}\\Microsoft\\WinGet\\Packages\\DenoLand.Deno_Microsoft.Winget.Source_8wekyb3d8bbwe\\deno.exe",
                "${LOCALAPPDATA}\\Programs\\bin\\deno.exe",
                "${HOME}\\.local\\bin\\deno.exe",
                "${ProgramFiles}\\Deno\\deno.exe",
                "${ProgramFiles(x86)}\\Deno\\deno.exe",
            ];
        });
    }
}