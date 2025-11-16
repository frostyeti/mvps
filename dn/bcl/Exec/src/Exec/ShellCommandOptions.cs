using FrostYeti.IO;

namespace FrostYeti.Exec;

public class ShellCommandOptions : CommandOptions
{

    public CommandArgs ScriptArgs { get; set; } = [];

    public virtual string[] FileExtensions { get; set; } = [];

    public string Script { get; set; } = string.Empty;

    public bool UseScriptAsFile { get; set; } = false;

    public string? DefaultExtension { get; set; }

    protected override CommandArgs FinalizeArgs()
    {
        var args = this.ScriptArgs.ToList();
        if (!this.Script.IsNullOrWhiteSpace())
        {
            args.Add(this.Script);
        }

        return new CommandArgs(args);
    }

    protected string GenerateDisposableFile(string script, string? extension = null)
    {
        var ext = extension ?? this.DefaultExtension ?? this.FileExtensions[0];

        var tmpDir = FrostYeti.Env.Get("HYPRX_TEMP_DIR") ?? System.IO.Path.GetTempPath();
        var tempFileName = Path.GetRandomFileName();
        var tempFile = Path.Combine(tmpDir, $"{tempFileName}{ext}");
        System.IO.File.WriteAllText(tempFile, script);
        var disposable = new DisposableFile(tempFile, (self) => this.Disposables.Remove(self));
        this.Disposables.Add(disposable);
        return tempFile;
    }
}