using System.Runtime.Versioning;

namespace FrostYeti.Exec;

public class Command<TCommand, TOptions> : ICommandOptionsOwner
    where TCommand : Command<TCommand, TOptions>, new()
    where TOptions : CommandOptions, new()
{
    public TOptions Options { get; set; } = new();

    CommandOptions ICommandOptionsOwner.Options => this.Options;

    public TCommand WithExecutable(string executable)
    {
        this.Options.File = executable;
        return (TCommand)this;
    }

    public TCommand WithArgs(CommandArgs args)
    {
        this.Options.Args = args;
        return (TCommand)this;
    }

    public TCommand WithCwd(string cwd)
    {
        this.Options.Cwd = cwd;
        return (TCommand)this;
    }

    public TCommand WithEnv(IDictionary<string, string?> env)
    {
        this.Options.Env = env;
        return (TCommand)this;
    }

    public TCommand SetEnv(string name, string value)
    {
        this.Options.Env ??= new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        this.Options.Env[name] = value;
        return (TCommand)this;
    }

    public TCommand SetEnv(IEnumerable<KeyValuePair<string, string?>> values)
    {
        this.Options.Env ??= new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        foreach (var kvp in values)
        {
            this.Options.Env[kvp.Key] = kvp.Value;
        }

        return (TCommand)this;
    }

    public TCommand WithDisposables(IEnumerable<IDisposable> disposables)
    {
        this.Options.Disposables.AddRange(disposables);
        return (TCommand)this;
    }

    public TCommand SetDisposables(IEnumerable<IDisposable> disposables)
    {
        this.Options.Disposables = new List<IDisposable>(disposables);
        return (TCommand)this;
    }

    public TCommand WithStdout(Stdio stdio)
    {
        this.Options.Stdout = stdio;
        return (TCommand)this;
    }

    public TCommand WithStderr(Stdio stdio)
    {
        this.Options.Stderr = stdio;
        return (TCommand)this;
    }

    public TCommand WithStdin(Stdio stdio)
    {
        this.Options.Stdin = stdio;
        return (TCommand)this;
    }

    public TCommand AsPiped()
    {
        this.Options.Stdout = Stdio.Piped;
        this.Options.Stderr = Stdio.Piped;
        this.Options.Stdin = Stdio.Piped;
        return (TCommand)this;
    }

    public TCommand AsOutput()
    {
        this.Options.Stdout = Stdio.Piped;
        this.Options.Stderr = Stdio.Piped;
        this.Options.Stdin = Stdio.Inherit;
        return (TCommand)this;
    }

    public TCommand WithStdio(Stdio stdio)
    {
        this.Options.Stdout = stdio;
        this.Options.Stderr = stdio;
        this.Options.Stdin = stdio;
        return (TCommand)this;
    }

    public TCommand WithVerb(string verb)
    {
        this.Options.Verb = verb;
        return (TCommand)this;
    }

    public TCommand AsWindowsAdmin()
    {
        this.Options.Verb = "runas";
        return (TCommand)this;
    }

    public TCommand AsSudo()
    {
        this.Options.Verb = "sudo";
        return (TCommand)this;
    }

    [SupportedOSPlatform("windows")]
    public TCommand WithUser(string user)
    {
        this.Options.User = user;
        return (TCommand)this;
    }

    [SupportedOSPlatform("windows")]
    public TCommand WithPassword(string password)
    {
        this.Options.PasswordInClearText = password;
        return (TCommand)this;
    }

    [SupportedOSPlatform("windows")]
    public TCommand WithDomain(string domain)
    {
        this.Options.Domain = domain;
        return (TCommand)this;
    }

    /// <summary>
    /// Gets or sets the input stream. This is only used when running the command. Spawning a command will
    /// not use this stream.
    /// </summary>
    public Stream? Input { get; set; }

    protected List<IDisposable> Disposables { get; } = [];

    public TCommand AddDisposable(IDisposable disposable)
    {
        this.Disposables.Add(disposable);
        return (TCommand)this;
    }

    public CommandPipe Pipe(CommandOptions command)
    {
        var pipe = new CommandPipe();
        pipe.Pipe(this);
        pipe.Pipe(command);
        return pipe;
    }

    public CommandPipe Pipe(CommandArgs args)
    {
        var pipe = new CommandPipe();
        pipe.Pipe(this);
        pipe.Pipe(args);
        return pipe;
    }

    public CommandPipe Pipe(ICommandOptionsOwner command)
    {
        var pipe = new CommandPipe();
        pipe.Pipe(this);
        pipe.Pipe(command);
        return pipe;
    }

    public Output Output(CommandArgs args)
    {
        var stdout = this.Options.Stdout;
        var stderr = this.Options.Stderr;

        this.Options.Stdout = Stdio.Piped;
        this.Options.Stderr = Stdio.Piped;

        var o = this.Run(args);

        this.Options.Stdout = stdout;
        this.Options.Stderr = stderr;
        return o;
    }

    public Output Output()
    {
        var stdout = this.Options.Stdout;
        var stderr = this.Options.Stderr;

        this.Options.Stdout = Stdio.Piped;
        this.Options.Stderr = Stdio.Piped;

        var o = this.Run();

        this.Options.Stdout = stdout;
        this.Options.Stderr = stderr;

        return o;
    }

    public async ValueTask<Output> OutputAsync(CommandArgs args, CancellationToken cancellationToken = default)
    {
        var oldStdout = this.Options.Stdout;
        var oldStderr = this.Options.Stderr;

        this.Options.Stdout = Stdio.Piped;
        this.Options.Stderr = Stdio.Piped;
        var output = await this.RunAsync(args, cancellationToken);

        this.Options.Stdout = oldStdout;
        this.Options.Stderr = oldStderr;

        return output;
    }

    public async ValueTask<Output> OutputAsync(CancellationToken cancellationToken = default)
    {
        var oldStdout = this.Options.Stdout;
        var oldStderr = this.Options.Stderr;

        this.Options.Stdout = Stdio.Piped;
        this.Options.Stderr = Stdio.Piped;
        var output = await this.RunAsync(cancellationToken);

        this.Options.Stdout = oldStdout;
        this.Options.Stderr = oldStderr;

        return output;
    }

    public Output Run(CommandArgs args)
    {
        var old = this.Options.Args;
        this.Options.Args = args;
        var output = this.Run();
        this.Options.Args = old;
        return output;
    }

    public Output Run()
    {
        var hasInput = this.Input is not null;
        if (hasInput)
        {
            this.Options.Stdin = Stdio.Piped;
        }

        using var process = new ChildProcess(this.Options);
        if (hasInput)
        {
            process.PipeFrom(this.Input!);
        }

        process.AddDisposables(this.Disposables);
        return process.WaitForOutput();
    }

    public async ValueTask<Output> RunAsync(CommandArgs args, CancellationToken cancellationToken = default)
    {
        var old = this.Options.Args;
        this.Options.Args = args;

        var output = await this.RunAsync(cancellationToken);

        this.Options.Args = old;

        return output;
    }

    public async ValueTask<Output> RunAsync(CancellationToken cancellationToken = default)
    {
        var hasInput = this.Input is not null;
        if (hasInput)
        {
            this.Options.Stdin = Stdio.Piped;
        }

        using var process = new ChildProcess(this.Options);
        if (hasInput)
        {
            process.PipeFrom(this.Input!);
        }

        process.AddDisposables(this.Disposables);
        var output = await process.WaitForOutputAsync(cancellationToken);
        return output;
    }

    public ChildProcess Spawn()
    {
        var process = new ChildProcess(this.Options);
        process.AddDisposables(this.Disposables);
        return process;
    }

    public ChildProcess Spawn(CommandArgs args)
    {
        this.Options.Args = args;
        var process = this.Spawn();
        this.Options.Args.Clear();
        return process;
    }
}