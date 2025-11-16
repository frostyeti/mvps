namespace FrostYeti.Exec;

public sealed class ShCommand : ShellCommand<ShCommand, ShCommandOptions>
{
    public ShCommand()
    {
    }

    public ShCommand(string script)
    {
        this.Options.Script = script;
    }

    /// <summary>
    /// Registers the PowerShell Core (pwsh) path hint with the default path finder.
    /// </summary>
    /// <remarks>
    /// <para>
    ///   The environment variable <c>PWSH_EXE</c> can be used to specify the path to the PowerShell Core executable
    ///   and it takes precedence over the default paths.
    /// </para>
    /// <para>
    ///   The default paths for windows look under Program Files for PowerShell versions 6 and 7, including
    ///   preview versions. For Linux, it checks common locations like `/usr/bin/pwsh` and `/usr/local/bin/pwsh`.
    /// </para>
    /// </remarks>
    public static void RegisterPathHint()
    {
        PathFinder.Default.RegisterOrUpdate("sh", (hint) =>
        {
            hint.Executable = "sh";
            hint.Variable = "SH_EXE";
            hint.Windows = [
                "${ProgramFiles}\\Git\\usr\\bin\\sh.exe",
            ];
            hint.Linux = [
                "/usr/bin/sh",
                "/usr/local/bin/sh",
            ];
        });
    }
}