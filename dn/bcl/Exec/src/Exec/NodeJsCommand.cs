namespace FrostYeti.Exec;

public sealed class NodeJsCommand : ShellCommand<NodeJsCommand, NodeJsCommandOptions>
{
    public NodeJsCommand()
    {
    }

    public NodeJsCommand(string script)
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
    ///   The default paths for windows look under Program Files for Git NodeJs. For Linux, it
    ///   checks common locations like `/usr/bin/bash` and `/usr/local/bin/bash`.
    /// </para>
    /// </remarks>
    public static void RegisterPathHint()
    {
        PathFinder.Default.RegisterOrUpdate("node", (hint) =>
        {
            hint.Variable = "NODE_EXE";
            hint.Linux = [
                "/usr/bin/node",
                "/usr/local/bin/node",
                "${XDG_DATA_HOME}/fnm/aliases/default/bin/node",
                "${HOME}/.local/share/fnm/aliases/default/bin/node",
                "${HOME}/.fnm/aliases/default/bin/node",
            ];

            hint.Windows = [
                "${HOME}\\.fnm\\aliases\\default\\bin\\node.exe",
                "${LOCALAPPDATA}\\fnm\\aliases\\default\\bin\\node.exe",
                "${XDG_DATA_HOME}\\fnm\\aliases\\default\\bin\\node.exe",
                "${ProgramFiles}\\nodejs\\node.exe",
                "${ProgramFiles(x86)}\\nodejs\\node.exe",
            ];
        });
    }
}