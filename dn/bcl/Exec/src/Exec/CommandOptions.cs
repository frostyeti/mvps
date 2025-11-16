using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security;

namespace FrostYeti.Exec;

public class CommandOptions
{
    public Action<ProcessStartInfo>? WriteCommand { get; set; }

    public string File { get; internal protected set; } = string.Empty;

    public CommandArgs Args { get; internal protected set; } = [];

    public string? Cwd { get; set; }

    public IDictionary<string, string?>? Env { get; set; }

    public List<IDisposable> Disposables { get; internal protected set; } = [];

    public Stdio Stdout { get; set; }

    public Stdio Stderr { get; set; }

    public Stdio Stdin { get; set; }

    public string? User { get; set; }

    public string? Verb { get; set; }

    [SupportedOSPlatform("windows")]
    [CLSCompliant(false)]
    public SecureString? Password { get; set; }

    [SupportedOSPlatform("windows")]
    public string? PasswordInClearText { get; set; }

    [SupportedOSPlatform("windows")]
    public string? Domain { get; set; }

    public bool LoadUserProfile { get; set; } = false;

    public bool CreateNoWindow { get; set; } = false;

    public bool UseShellExecute { get; set; } = false;

    public virtual ProcessStartInfo ToStartInfo()
    {
        var si = new ProcessStartInfo();
        return this.ToStartInfo(si);
    }

    public virtual ProcessStartInfo ToStartInfo(ProcessStartInfo startInfo)
    {
        var si = startInfo;
        si.FileName = this.File;
        var exe = PathFinder.Default.Find(this.File);
        if (!exe.IsNullOrWhiteSpace())
        {
            si.FileName = exe;
        }

        si.CreateNoWindow = this.CreateNoWindow;
        si.UseShellExecute = this.UseShellExecute;
        si.RedirectStandardInput = this.Stdin == Stdio.Piped;

        var windows = RuntimeInformation.IsOSPlatform(OSPlatform.Windows);

        if (windows)
            si.LoadUserProfile = startInfo.LoadUserProfile;

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows) && !this.User.IsNullOrWhiteSpace())
        {
            si.UserName = this.User;

            if (startInfo.Password is not null)
            {
                si.Password = startInfo.Password;
            }
            else if (!startInfo.PasswordInClearText.IsNullOrWhiteSpace())
            {
                si.PasswordInClearText = startInfo.PasswordInClearText;
            }

            if (!startInfo.Domain.IsNullOrWhiteSpace())
            {
                si.Domain = startInfo.Domain;
            }
        }

        var args = this.FinalizeArgs();

#if NET5_0_OR_GREATER
        foreach (var arg in args)
        {
            si.ArgumentList.Add(arg);
        }
#else
        si.Arguments = args.ToString();
#endif

        if (!this.Cwd.IsNullOrWhiteSpace())
            si.WorkingDirectory = this.Cwd;

        if (this.Env is not null)
        {
            foreach (var kvp in this.Env)
            {
                si.Environment[kvp.Key] = kvp.Value;
            }
        }

        si.RedirectStandardOutput = this.Stdout != Stdio.Inherit;
        si.RedirectStandardError = this.Stderr != Stdio.Inherit;
        si.RedirectStandardInput = this.Stdin != Stdio.Inherit;
        if (si.RedirectStandardError || si.RedirectStandardOutput)
        {
            si.CreateNoWindow = true;
            si.UseShellExecute = false;
        }

        return si;
    }

    protected virtual CommandArgs FinalizeArgs()
        => this.Args;
}