using System.Runtime.CompilerServices;
using System.Runtime.Versioning;

namespace FrostYeti.Exec;

public class ShellCommand<TCommand, TOptions> : Command<TCommand, TOptions>
    where TCommand : ShellCommand<TCommand, TOptions>, new()
    where TOptions : ShellCommandOptions, new()
{
    private CancellationToken? cancellationToken;

    public ValueTaskAwaiter<Output> GetAwaiter()
    {
        var token = this.cancellationToken ?? default;
        if (this.Options.Script.IsNullOrWhiteSpace())
            return this.RunAsync(token).GetAwaiter();

        return this.RunScriptAsync(token).GetAwaiter();
    }

    public TCommand WithCancellationToken(CancellationToken cancellationToken)
    {
        this.cancellationToken = cancellationToken;
        return (TCommand)this;
    }

    public TCommand WithScript(string script)
    {
        this.Options.Script = script;
        return (TCommand)this;
    }

    public TCommand WithScriptArgs(CommandArgs args)
    {
        this.Options.ScriptArgs = args ?? [];
        return (TCommand)this;
    }

    public TCommand AddScriptArgs(params string[] args)
    {
        this.Options.ScriptArgs.AddRange(args ?? []);
        return (TCommand)this;
    }

    public TCommand WithRunScriptAsFile(bool useScriptAsFile = true)
    {
        this.Options.UseScriptAsFile = useScriptAsFile;
        return (TCommand)this;
    }

    public TCommand WithDefaultExtension(string? defaultExtension)
    {
        this.Options.DefaultExtension = defaultExtension;
        return (TCommand)this;
    }

    public Output OutputScript()
    {
        this.Options.Stdout = Stdio.Piped;
        this.Options.Stderr = Stdio.Piped;
        return this.RunScript();
    }

    public Output OutputScript(string script)
    {
        this.Options.Stdout = Stdio.Piped;
        this.Options.Stderr = Stdio.Piped;
        return this.RunScript(script);
    }

    public ValueTask<Output> OutputScriptAsync(string script, CancellationToken cancellationToken = default)
    {
        this.Options.Stdout = Stdio.Piped;
        this.Options.Stderr = Stdio.Piped;
        return this.RunScriptAsync(script, cancellationToken);
    }

    public ValueTask<Output> OutputScriptAsync(CancellationToken cancellationToken = default)
    {
        this.Options.Stdout = Stdio.Piped;
        this.Options.Stderr = Stdio.Piped;
        return this.RunScriptAsync(cancellationToken);
    }

    public Output RunScript(string script)
    {
        this.Options.Script = script;
        return this.Run();
    }

    public Output RunScript()
    {
        if (this.Options.Script.IsNullOrWhiteSpace())
        {
            return new Output(
                this.Options.File,
                -1,
                new InvalidOperationException(" No script provided to run. The ShellCommandOptions.Script property must be set for RunScript method."),
                [],
                [],
                DateTime.UtcNow,
                DateTime.UtcNow);
        }

        return this.Run();
    }

    public ValueTask<Output> RunScriptAsync(string script, CancellationToken cancellationToken = default)
    {
        this.Options.Script = script;
        return this.RunAsync(cancellationToken);
    }

    public ValueTask<Output> RunScriptAsync(CancellationToken cancellationToken = default)
    {
        if (this.Options.Script.IsNullOrWhiteSpace())
        {
            return new ValueTask<Output>(new Output(
                this.Options.File,
                -1,
                new InvalidOperationException(" No script provided to run. The ShellCommandOptions.Script property must be set for RunScriptAsync method."),
                [],
                [],
                DateTime.UtcNow,
                DateTime.UtcNow));
        }

        return this.RunAsync(cancellationToken);
    }
}