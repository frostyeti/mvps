namespace FrostYeti.Exec;

public sealed class DenoCommandOptions : ShellCommandOptions
{
    public DenoCommandOptions()
    {
        this.File = "deno";
        this.FileExtensions = [".ts", ".js", ".mjs", ".tsx", ".jsx"];
    }

    protected override CommandArgs FinalizeArgs()
    {
        if (this.Script.IsNullOrWhiteSpace())
        {
            throw new InvalidOperationException("Script must be set to get script arguments.");
        }

        var script = this.Script.Trim();
        var isFilePath = !script.Any(o => o is '\n' or '\r') &&
                          this.FileExtensions.Any(ext => script.EndsWith(ext, StringComparison.OrdinalIgnoreCase));

        var args = this.ScriptArgs.ToList();

        if (isFilePath || this.UseScriptAsFile)
        {
            string file = string.Empty;
            if (!isFilePath)
            {
                file = this.GenerateDisposableFile(this.Script);
            }
            else
            {
                file = script;
            }

            if (args.Count == 0)
            {
                args.AddRange(["run", "--allow-all", "--allow-scripts"]);
            }

            args.Add(file);
            return [.. args];
        }

        if (args.Count == 0)
        {
            args.AddRange(["eval", "--allow-scripts"]);
        }

        args.Add(this.Script);
        return [.. args];
    }
}