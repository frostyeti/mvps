namespace FrostYeti.Exec;

public sealed class WinCommand : ShellCommand<WinCommand, WinCommandOptions>, ICommandOptionsOwner
{
    public WinCommand()
    {
    }

    public WinCommand(string script)
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
        PathFinder.Default.RegisterOrUpdate("cmd", (hint) =>
        {
            hint.Executable = "cmd";
            hint.Variable = "CMD_EXE";
            hint.Windows = [
            "${SystemRoot}\\System32\\cmd.exe",
            ];
        });
    }
}