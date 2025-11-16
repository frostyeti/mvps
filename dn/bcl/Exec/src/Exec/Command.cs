using System.Runtime.CompilerServices;
using System.Runtime.Versioning;

namespace FrostYeti.Exec;

public partial class Command : Command<Command, CommandOptions>, ICommandOptionsOwner
{
    private CancellationToken? cancellationToken;

    public Command()
    {
    }

    public Command(CommandArgs args)
        : this()
    {
        ArgumentOutOfRangeException.ThrowIfNullOrEmpty(args);
        var exe = args[0];
        args.RemoveAt(0);
        this.Options.File = exe;
        this.Options.Args = args;
    }

    public Command(CommandOptions options)
    {
        this.Options = options;
    }

    public ValueTaskAwaiter<Output> GetAwaiter()
    {
        var token = this.cancellationToken ?? default;
        return this.RunAsync(token).GetAwaiter();
    }

    public Command WithCancellationToken(CancellationToken cancellationToken)
    {
        this.cancellationToken = cancellationToken;
        return this;
    }
}