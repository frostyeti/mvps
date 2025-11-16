namespace FrostYeti.Exec;

public sealed class RubyCommand : ShellCommand<RubyCommand, RubyCommandOptions>
{
    public RubyCommand()
    {
    }

    public RubyCommand(string script)
    {
        this.Options.Script = script;
    }

    /// <summary>
    /// Registers the bash path hint with the default path finder.
    /// </summary>
    /// <remarks>
    /// <para>
    ///   The environment variable <c>PYTHON_EXE</c> can be used to specify the path to the Ruby executable
    ///   and it takes precedence over the default paths.
    /// </para>
    /// <para>
    ///   The default paths for windows look under Program Files for Git Ruby. For Linux, it
    ///   checks common locations like `/usr/bin/python3` and `/usr/local/bin/python3`.
    /// </para>
    /// </remarks>
    public static void RegisterPathHint()
    {
        PathFinder.Default.RegisterOrUpdate("ruby", (hint) =>
        {
            hint.Variable = "RUBY_EXE";
            hint.Linux = [
                "/usr/bin/ruby",
                "/usr/local/bin/ruby",
            ];

            hint.Windows = [
                "C:\\Ruby31-x64\\bin\\ruby.exe",
                "C:\\Ruby32-x64\\bin\\ruby.exe",
                "C:\\Ruby33-x64\\bin\\ruby.exe",
            ];
        });
    }
}